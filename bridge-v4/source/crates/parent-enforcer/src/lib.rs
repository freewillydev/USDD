//! Header-only parent-miner commitment verification for ECX.
//!
//! The production miner boundary is [`verify_miner_header_commitment`]. It
//! accepts one serialized Elements critical-header preimage plus local BMM and
//! header-chain context. It has no Truthcoin, matcher, Simplicity, SP1, private
//! witness, or M6 body input. ECX state-transition and `PXST` correctness are
//! child-chain consensus rules; BIP300 treats the header's withdrawal bundle
//! hash as an opaque commitment and BIP301 treats the critical hash likewise.
//!
//! The older semantic PXST adapter remains below as a compatibility/reference
//! surface only. It must not be wired into a production miner vote path.

#![forbid(unsafe_code)]

#[cfg(feature = "legacy-pxst-reference")]
use ecx_protocol_core::{
    verify_child_withdrawal_state_commitment, AuthenticatedChildCheckpointV1, ProtocolError,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub type Hash32 = [u8; 32];
pub const BMM_SLOT: u8 = 24;

pub const PARENT_ENFORCER_ADAPTER_VERSION: u8 = 1;
#[cfg(feature = "legacy-pxst-reference")]
pub const LEGACY_M6_POLICY_VERSION: u8 = 1;
pub const MAX_CRITICAL_HEADER_BYTES: usize = 64 * 1024;
pub const MIN_CRITICAL_HEADER_BYTES: usize = BMM_PROOF_END + ECX_HEADER_SUFFIX_BYTES;
#[cfg(feature = "legacy-pxst-reference")]
pub const MAX_M6_BYTES: usize = 1024 * 1024;
#[cfg(feature = "legacy-pxst-reference")]
pub const MAX_SCRIPT_BYTES: usize = 10_000;

pub const WITHDRAWAL_HEADER_MASK: u32 = 1 << 30;
pub const BMM_PROOF_HEADER_MASK: u32 = 1 << 20;
pub const EXCHANGE_STATE_HEADER_MASK: u32 = 1 << 19;
pub const FORCED_INBOX_HEADER_MASK: u32 = 1 << 18;
pub const DEPOSIT_INBOX_HEADER_MASK: u32 = 1 << 17;
pub const REQUIRED_ECX_WITHDRAWAL_HEADER_MASK: u32 = WITHDRAWAL_HEADER_MASK
    | BMM_PROOF_HEADER_MASK
    | EXCHANGE_STATE_HEADER_MASK
    | FORCED_INBOX_HEADER_MASK
    | DEPOSIT_INBOX_HEADER_MASK;

const PREVIOUS_CHILD_HASH_START: usize = 4;
const PREVIOUS_CHILD_HASH_END: usize = 36;
const WITHDRAWAL_M6ID_START: usize = 68;
const WITHDRAWAL_M6ID_END: usize = 100;
const BMM_PROOF_START: usize = 100;
const BMM_PROOF_END: usize = 132;
const ECX_HEADER_SUFFIX_BYTES: usize = 100;

/// Frozen deployment identity. This must be set from local configuration, not
/// from an Elements RPC response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParentEnforcerConfigV1 {
    pub version: u8,
    pub sidechain_slot: u8,
    pub child_genesis_hash: Hash32,
}

/// One slot commitment selected from the parent enforcer's already validated
/// BMM database. The parent block identity is carried through the approval
/// result for an auditable vote decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocallyValidatedBmmCommitmentV1 {
    pub version: u8,
    pub sidechain_slot: u8,
    /// Raw 32 bytes committed by BMM, never reversed display hex.
    pub critical_hash: Hash32,
    pub approving_parent_block_hash: Hash32,
    pub approving_parent_height: u32,
}

/// Child-chain position maintained by the enforcer. The header itself does
/// not serialize its height or genesis, so neither value may come from the
/// untrusted header transport.
#[cfg(feature = "legacy-pxst-reference")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocallyValidatedChildCheckpointV1 {
    pub version: u8,
    pub child_genesis_hash: Hash32,
    pub checkpoint_height: u32,
    pub previous_child_block_hash: Hash32,
    pub expected_exchange_state_root: Hash32,
    pub expected_forced_inbox_root: Hash32,
    pub expected_deposit_inbox_root: Hash32,
    /// The exact `nVersion` expected by the local child-chain index.
    pub expected_header_version: u32,
    /// Exact serialized critical-preimage size recorded by the local index.
    pub critical_header_len: u32,
}

#[cfg(feature = "legacy-pxst-reference")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WithdrawalOutpointV1 {
    /// Raw transaction-id consensus bytes, never reversed display hex.
    pub txid: Hash32,
    pub vout: u32,
}

/// Legacy M6 facts authenticated by the existing enforcer policy. Requiring
/// them here prevents this additive adapter from weakening outputs 0 through 2.
#[cfg(feature = "legacy-pxst-reference")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyM6PolicyV1 {
    pub version: u8,
    pub withdrawal_outpoint: WithdrawalOutpointV1,
    pub expected_mainchain_fee_sats: u64,
    pub expected_payout_sats: u64,
    pub expected_payout_script: Vec<u8>,
}

#[cfg(feature = "legacy-pxst-reference")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovedParentWithdrawalV1 {
    pub sidechain_slot: u8,
    pub critical_hash: Hash32,
    pub approving_parent_block_hash: Hash32,
    pub source_parent_height: u32,
    pub checkpoint_height: u32,
    pub previous_child_block_hash: Hash32,
    pub withdrawal_m6id: Hash32,
    pub existing_withdrawal_commitment: Hash32,
    pub exchange_state_root: Hash32,
    pub forced_inbox_root: Hash32,
    pub deposit_inbox_root: Hash32,
}

/// Local context needed to authenticate one Elements header in the child
/// header chain. It deliberately contains no expected ECX state value: miners
/// commit to the header bytes but do not execute the ECX state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderOnlyChildContextV1 {
    pub version: u8,
    pub child_genesis_hash: Hash32,
    pub checkpoint_height: u32,
    pub previous_child_block_hash: Hash32,
    pub expected_header_version: u32,
    pub critical_header_len: u32,
}

/// Opaque commitments extracted from an authenticated Elements header.
/// Returning these values does not assert that the hidden ECX transition is
/// correct; Elements full nodes make that consensus decision before building
/// on the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedHeaderCommitmentV1 {
    pub sidechain_slot: u8,
    pub critical_hash: Hash32,
    pub approving_parent_block_hash: Hash32,
    pub checkpoint_height: u32,
    pub previous_child_block_hash: Hash32,
    pub withdrawal_bundle_hash: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ApprovalError {
    #[error("invalid parent-enforcer configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("invalid locally validated BMM record: {0}")]
    InvalidBmmRecord(&'static str),
    #[error("invalid locally validated child checkpoint: {0}")]
    InvalidCheckpoint(&'static str),
    #[error("critical header is outside the bounded size")]
    CriticalHeaderSize,
    #[error("malformed critical header: {0}")]
    MalformedCriticalHeader(&'static str),
    #[error("critical header authentication mismatch: {0}")]
    CriticalHeaderMismatch(&'static str),
    #[cfg(feature = "legacy-pxst-reference")]
    #[error("M6 is outside the bounded size")]
    M6Size,
    #[cfg(feature = "legacy-pxst-reference")]
    #[error("unexpected end of M6")]
    UnexpectedEnd,
    #[cfg(feature = "legacy-pxst-reference")]
    #[error("M6 has a non-canonical CompactSize integer")]
    NonCanonicalCompactSize,
    #[cfg(feature = "legacy-pxst-reference")]
    #[error("malformed M6: {0}")]
    MalformedM6(&'static str),
    #[cfg(feature = "legacy-pxst-reference")]
    #[error("legacy M6 policy mismatch: {0}")]
    LegacyM6Mismatch(&'static str),
    #[cfg(feature = "legacy-pxst-reference")]
    #[error("withdrawal-state approval policy refused the marker: {0}")]
    Protocol(#[from] ProtocolError),
}

/// Authenticate exactly one Elements critical-header preimage against the
/// BIP301 commitment and the locally tracked child-header ancestry.
///
/// This is the complete ECX-specific miner interface. Standard BIP300 code may
/// separately process the opaque `withdrawal_bundle_hash`; it must not call
/// Truthcoin or re-run ECX/Simplicity/SP1/PXST validation.
pub fn verify_miner_header_commitment(
    config: &ParentEnforcerConfigV1,
    bmm: &LocallyValidatedBmmCommitmentV1,
    context: &HeaderOnlyChildContextV1,
    critical_header_preimage: &[u8],
) -> Result<AcceptedHeaderCommitmentV1, ApprovalError> {
    validate_header_only_inputs(config, bmm, context)?;
    let withdrawal_bundle_hash =
        parse_header_only_commitment(bmm, context, critical_header_preimage)?;

    Ok(AcceptedHeaderCommitmentV1 {
        sidechain_slot: bmm.sidechain_slot,
        critical_hash: bmm.critical_hash,
        approving_parent_block_hash: bmm.approving_parent_block_hash,
        checkpoint_height: context.checkpoint_height,
        previous_child_block_hash: context.previous_child_block_hash,
        withdrawal_bundle_hash,
    })
}

/// Verify the complete parent-side decision before approving an ECX M6.
///
/// No decoded field from a child RPC is accepted. The raw header and M6 are
/// bounded, hashed, parsed and cross-checked against local records here.
#[cfg(feature = "legacy-pxst-reference")]
pub fn verify_parent_miner_pxst_approval(
    config: &ParentEnforcerConfigV1,
    bmm: &LocallyValidatedBmmCommitmentV1,
    checkpoint: &LocallyValidatedChildCheckpointV1,
    critical_header_preimage: &[u8],
    legacy_policy: &LegacyM6PolicyV1,
    m6_bytes: &[u8],
) -> Result<ApprovedParentWithdrawalV1, ApprovalError> {
    validate_local_inputs(config, bmm, checkpoint, legacy_policy)?;
    let header = parse_and_authenticate_critical_header(bmm, checkpoint, critical_header_preimage)?;
    let m6 = parse_m6(m6_bytes)?;

    let existing_withdrawal_commitment = withdrawal_inputs_commitment(
        legacy_policy.withdrawal_outpoint,
        checkpoint.checkpoint_height,
    );
    authenticate_legacy_m6(&m6, legacy_policy, existing_withdrawal_commitment)?;

    if m6.m6id != header.withdrawal_m6id {
        return Err(ApprovalError::CriticalHeaderMismatch("withdrawal M6ID"));
    }

    let authenticated_checkpoint = AuthenticatedChildCheckpointV1 {
        slot: bmm.sidechain_slot,
        child_genesis_hash: checkpoint.child_genesis_hash,
        checkpoint_height: checkpoint.checkpoint_height,
        previous_child_block_hash: checkpoint.previous_child_block_hash,
        exchange_state_root: header.exchange_state_root,
    };
    let scripts: Vec<Vec<u8>> = m6
        .outputs
        .iter()
        .map(|output| output.script.clone())
        .collect();
    verify_child_withdrawal_state_commitment(
        &authenticated_checkpoint,
        existing_withdrawal_commitment,
        &scripts,
    )?;

    Ok(ApprovedParentWithdrawalV1 {
        sidechain_slot: bmm.sidechain_slot,
        critical_hash: bmm.critical_hash,
        approving_parent_block_hash: bmm.approving_parent_block_hash,
        source_parent_height: header.source_parent_height,
        checkpoint_height: checkpoint.checkpoint_height,
        previous_child_block_hash: checkpoint.previous_child_block_hash,
        withdrawal_m6id: m6.m6id,
        existing_withdrawal_commitment,
        exchange_state_root: header.exchange_state_root,
        forced_inbox_root: header.forced_inbox_root,
        deposit_inbox_root: header.deposit_inbox_root,
    })
}

/// Bitcoin `SHA256d`, returned in the raw digest byte order used in consensus
/// serialization and BMM records.
pub fn bitcoin_double_sha256(bytes: &[u8]) -> Hash32 {
    let first: Hash32 = Sha256::digest(bytes).into();
    Sha256::digest(first).into()
}

/// Reconstruct the pre-existing branch commitment without replacing it:
/// `SerializeHash([withdrawal_outpoint, OutPoint(0, checkpoint_height)])`.
#[cfg(feature = "legacy-pxst-reference")]
pub fn withdrawal_inputs_commitment(
    withdrawal_outpoint: WithdrawalOutpointV1,
    checkpoint_height: u32,
) -> Hash32 {
    let mut bytes = Vec::with_capacity(1 + 2 * (32 + 4));
    bytes.push(2); // canonical CompactSize vector length
    bytes.extend_from_slice(&withdrawal_outpoint.txid);
    bytes.extend_from_slice(&withdrawal_outpoint.vout.to_le_bytes());
    bytes.extend_from_slice(&[0; 32]);
    bytes.extend_from_slice(&checkpoint_height.to_le_bytes());
    bitcoin_double_sha256(&bytes)
}

fn validate_header_only_inputs(
    config: &ParentEnforcerConfigV1,
    bmm: &LocallyValidatedBmmCommitmentV1,
    context: &HeaderOnlyChildContextV1,
) -> Result<(), ApprovalError> {
    if config.version != PARENT_ENFORCER_ADAPTER_VERSION {
        return Err(ApprovalError::InvalidConfiguration("version"));
    }
    if config.sidechain_slot != BMM_SLOT {
        return Err(ApprovalError::InvalidConfiguration("slot"));
    }
    if config.child_genesis_hash == [0; 32] {
        return Err(ApprovalError::InvalidConfiguration("child genesis"));
    }

    if bmm.version != PARENT_ENFORCER_ADAPTER_VERSION {
        return Err(ApprovalError::InvalidBmmRecord("version"));
    }
    if bmm.sidechain_slot != config.sidechain_slot {
        return Err(ApprovalError::InvalidBmmRecord("slot"));
    }
    if bmm.critical_hash == [0; 32]
        || bmm.approving_parent_block_hash == [0; 32]
        || bmm.approving_parent_height == 0
    {
        return Err(ApprovalError::InvalidBmmRecord("zero field"));
    }

    if context.version != PARENT_ENFORCER_ADAPTER_VERSION {
        return Err(ApprovalError::InvalidCheckpoint("version"));
    }
    if context.child_genesis_hash != config.child_genesis_hash {
        return Err(ApprovalError::InvalidCheckpoint("child genesis"));
    }
    if context.checkpoint_height == 0 || context.previous_child_block_hash == [0; 32] {
        return Err(ApprovalError::InvalidCheckpoint("zero field"));
    }
    if context.expected_header_version & REQUIRED_ECX_WITHDRAWAL_HEADER_MASK
        != REQUIRED_ECX_WITHDRAWAL_HEADER_MASK
    {
        return Err(ApprovalError::InvalidCheckpoint("header version"));
    }
    let recorded_len = usize::try_from(context.critical_header_len)
        .map_err(|_| ApprovalError::InvalidCheckpoint("critical header length"))?;
    if !(MIN_CRITICAL_HEADER_BYTES..=MAX_CRITICAL_HEADER_BYTES).contains(&recorded_len) {
        return Err(ApprovalError::InvalidCheckpoint("critical header length"));
    }
    Ok(())
}

#[cfg(feature = "legacy-pxst-reference")]
fn validate_local_inputs(
    config: &ParentEnforcerConfigV1,
    bmm: &LocallyValidatedBmmCommitmentV1,
    checkpoint: &LocallyValidatedChildCheckpointV1,
    legacy: &LegacyM6PolicyV1,
) -> Result<(), ApprovalError> {
    if config.version != PARENT_ENFORCER_ADAPTER_VERSION {
        return Err(ApprovalError::InvalidConfiguration("version"));
    }
    if config.sidechain_slot != BMM_SLOT {
        return Err(ApprovalError::InvalidConfiguration("slot"));
    }
    if config.child_genesis_hash == [0; 32] {
        return Err(ApprovalError::InvalidConfiguration("child genesis"));
    }

    if bmm.version != PARENT_ENFORCER_ADAPTER_VERSION {
        return Err(ApprovalError::InvalidBmmRecord("version"));
    }
    if bmm.sidechain_slot != BMM_SLOT || bmm.sidechain_slot != config.sidechain_slot {
        return Err(ApprovalError::InvalidBmmRecord("slot"));
    }
    if bmm.critical_hash == [0; 32]
        || bmm.approving_parent_block_hash == [0; 32]
        || bmm.approving_parent_height == 0
    {
        return Err(ApprovalError::InvalidBmmRecord("zero field"));
    }

    if checkpoint.version != PARENT_ENFORCER_ADAPTER_VERSION {
        return Err(ApprovalError::InvalidCheckpoint("version"));
    }
    if checkpoint.child_genesis_hash != config.child_genesis_hash {
        return Err(ApprovalError::InvalidCheckpoint("child genesis"));
    }
    if checkpoint.child_genesis_hash == [0; 32]
        || checkpoint.checkpoint_height == 0
        || checkpoint.previous_child_block_hash == [0; 32]
        || checkpoint.expected_exchange_state_root == [0; 32]
        || checkpoint.expected_forced_inbox_root == [0; 32]
        || checkpoint.expected_deposit_inbox_root == [0; 32]
    {
        return Err(ApprovalError::InvalidCheckpoint("zero field"));
    }
    if checkpoint.expected_header_version & REQUIRED_ECX_WITHDRAWAL_HEADER_MASK
        != REQUIRED_ECX_WITHDRAWAL_HEADER_MASK
    {
        return Err(ApprovalError::InvalidCheckpoint("header version"));
    }
    let recorded_len = usize::try_from(checkpoint.critical_header_len)
        .map_err(|_| ApprovalError::InvalidCheckpoint("critical header length"))?;
    if !(MIN_CRITICAL_HEADER_BYTES..=MAX_CRITICAL_HEADER_BYTES).contains(&recorded_len) {
        return Err(ApprovalError::InvalidCheckpoint("critical header length"));
    }

    if legacy.version != LEGACY_M6_POLICY_VERSION {
        return Err(ApprovalError::InvalidConfiguration(
            "legacy M6 policy version",
        ));
    }
    if legacy.withdrawal_outpoint.txid == [0; 32] {
        return Err(ApprovalError::InvalidConfiguration("withdrawal outpoint"));
    }
    if legacy.expected_mainchain_fee_sats > i64::MAX as u64 {
        return Err(ApprovalError::InvalidConfiguration("mainchain fee"));
    }
    if legacy.expected_payout_sats == 0 || legacy.expected_payout_sats > i64::MAX as u64 {
        return Err(ApprovalError::InvalidConfiguration("payout value"));
    }
    if legacy.expected_payout_script.is_empty()
        || legacy.expected_payout_script.len() > MAX_SCRIPT_BYTES
    {
        return Err(ApprovalError::InvalidConfiguration("payout script"));
    }
    Ok(())
}

#[cfg(feature = "legacy-pxst-reference")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParsedCriticalHeaderV1 {
    withdrawal_m6id: Hash32,
    exchange_state_root: Hash32,
    forced_inbox_root: Hash32,
    deposit_inbox_root: Hash32,
    source_parent_height: u32,
}

fn parse_header_only_commitment(
    bmm: &LocallyValidatedBmmCommitmentV1,
    context: &HeaderOnlyChildContextV1,
    bytes: &[u8],
) -> Result<Hash32, ApprovalError> {
    if !(MIN_CRITICAL_HEADER_BYTES..=MAX_CRITICAL_HEADER_BYTES).contains(&bytes.len()) {
        return Err(ApprovalError::CriticalHeaderSize);
    }
    if bytes.len() != context.critical_header_len as usize {
        return Err(ApprovalError::CriticalHeaderMismatch("serialized length"));
    }

    let version = u32::from_le_bytes(
        bytes[0..4]
            .try_into()
            .map_err(|_| ApprovalError::MalformedCriticalHeader("version"))?,
    );
    if version != context.expected_header_version {
        return Err(ApprovalError::CriticalHeaderMismatch("version"));
    }
    if version & REQUIRED_ECX_WITHDRAWAL_HEADER_MASK != REQUIRED_ECX_WITHDRAWAL_HEADER_MASK {
        return Err(ApprovalError::MalformedCriticalHeader(
            "required extension bits",
        ));
    }

    let previous_child_block_hash =
        copy_hash(&bytes[PREVIOUS_CHILD_HASH_START..PREVIOUS_CHILD_HASH_END]);
    if previous_child_block_hash != context.previous_child_block_hash {
        return Err(ApprovalError::CriticalHeaderMismatch(
            "previous child block hash",
        ));
    }
    if bytes[BMM_PROOF_START..BMM_PROOF_END] != [0; 32] {
        return Err(ApprovalError::MalformedCriticalHeader(
            "BMM proof is not cleared",
        ));
    }
    if bitcoin_double_sha256(bytes) != bmm.critical_hash {
        return Err(ApprovalError::CriticalHeaderMismatch("BMM critical hash"));
    }

    let withdrawal_m6id = copy_hash(&bytes[WITHDRAWAL_M6ID_START..WITHDRAWAL_M6ID_END]);
    if withdrawal_m6id == [0; 32] {
        return Err(ApprovalError::MalformedCriticalHeader(
            "zero withdrawal M6ID",
        ));
    }

    Ok(withdrawal_m6id)
}

#[cfg(feature = "legacy-pxst-reference")]
fn parse_and_authenticate_critical_header(
    bmm: &LocallyValidatedBmmCommitmentV1,
    checkpoint: &LocallyValidatedChildCheckpointV1,
    bytes: &[u8],
) -> Result<ParsedCriticalHeaderV1, ApprovalError> {
    if !(MIN_CRITICAL_HEADER_BYTES..=MAX_CRITICAL_HEADER_BYTES).contains(&bytes.len()) {
        return Err(ApprovalError::CriticalHeaderSize);
    }
    if bytes.len() != checkpoint.critical_header_len as usize {
        return Err(ApprovalError::CriticalHeaderMismatch("serialized length"));
    }

    let version = u32::from_le_bytes(
        bytes[0..4]
            .try_into()
            .map_err(|_| ApprovalError::MalformedCriticalHeader("version"))?,
    );
    if version != checkpoint.expected_header_version {
        return Err(ApprovalError::CriticalHeaderMismatch("version"));
    }
    if version & REQUIRED_ECX_WITHDRAWAL_HEADER_MASK != REQUIRED_ECX_WITHDRAWAL_HEADER_MASK {
        return Err(ApprovalError::MalformedCriticalHeader(
            "required extension bits",
        ));
    }

    let previous_child_block_hash =
        copy_hash(&bytes[PREVIOUS_CHILD_HASH_START..PREVIOUS_CHILD_HASH_END]);
    if previous_child_block_hash != checkpoint.previous_child_block_hash {
        return Err(ApprovalError::CriticalHeaderMismatch(
            "previous child block hash",
        ));
    }
    if bytes[BMM_PROOF_START..BMM_PROOF_END] != [0; 32] {
        return Err(ApprovalError::MalformedCriticalHeader(
            "BMM proof is not cleared",
        ));
    }

    let critical_hash = bitcoin_double_sha256(bytes);
    if critical_hash != bmm.critical_hash {
        return Err(ApprovalError::CriticalHeaderMismatch("BMM critical hash"));
    }

    let suffix_start = bytes.len() - ECX_HEADER_SUFFIX_BYTES;
    if suffix_start < BMM_PROOF_END {
        return Err(ApprovalError::MalformedCriticalHeader("overlapping suffix"));
    }
    let exchange_state_root = copy_hash(&bytes[suffix_start..suffix_start + 32]);
    let forced_inbox_root = copy_hash(&bytes[suffix_start + 32..suffix_start + 64]);
    let deposit_inbox_root = copy_hash(&bytes[suffix_start + 64..suffix_start + 96]);
    if exchange_state_root == [0; 32]
        || forced_inbox_root == [0; 32]
        || deposit_inbox_root == [0; 32]
    {
        return Err(ApprovalError::MalformedCriticalHeader("zero ECX root"));
    }
    if exchange_state_root != checkpoint.expected_exchange_state_root {
        return Err(ApprovalError::CriticalHeaderMismatch("exchange state root"));
    }
    if forced_inbox_root != checkpoint.expected_forced_inbox_root {
        return Err(ApprovalError::CriticalHeaderMismatch("forced inbox root"));
    }
    if deposit_inbox_root != checkpoint.expected_deposit_inbox_root {
        return Err(ApprovalError::CriticalHeaderMismatch("deposit inbox root"));
    }
    let source_parent_height = u32::from_le_bytes(
        bytes[suffix_start + 96..suffix_start + 100]
            .try_into()
            .map_err(|_| ApprovalError::MalformedCriticalHeader("parent height"))?,
    );
    if source_parent_height == 0 {
        return Err(ApprovalError::MalformedCriticalHeader("zero parent height"));
    }
    if source_parent_height != bmm.approving_parent_height {
        return Err(ApprovalError::CriticalHeaderMismatch("parent height"));
    }

    let withdrawal_m6id = copy_hash(&bytes[WITHDRAWAL_M6ID_START..WITHDRAWAL_M6ID_END]);
    if withdrawal_m6id == [0; 32] {
        return Err(ApprovalError::MalformedCriticalHeader(
            "zero withdrawal M6ID",
        ));
    }

    Ok(ParsedCriticalHeaderV1 {
        withdrawal_m6id,
        exchange_state_root,
        forced_inbox_root,
        deposit_inbox_root,
        source_parent_height,
    })
}

fn copy_hash(bytes: &[u8]) -> Hash32 {
    let mut hash = [0; 32];
    hash.copy_from_slice(bytes);
    hash
}

#[cfg(feature = "legacy-pxst-reference")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct TxOutput {
    value: u64,
    script: Vec<u8>,
}

#[cfg(feature = "legacy-pxst-reference")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedM6 {
    outputs: [TxOutput; 4],
    m6id: Hash32,
}

#[cfg(feature = "legacy-pxst-reference")]
fn parse_m6(bytes: &[u8]) -> Result<ParsedM6, ApprovalError> {
    if bytes.len() > MAX_M6_BYTES {
        return Err(ApprovalError::M6Size);
    }
    let mut reader = Reader::new(bytes);
    let version = reader.i32_le()?;
    if version != 2 {
        return Err(ApprovalError::MalformedM6("version"));
    }

    // The branch may transport its inputless M6 with Bitcoin's witness
    // disambiguation marker (`00 01 00`) or in canonical txid form (`00`).
    if reader.u8()? != 0 {
        return Err(ApprovalError::MalformedM6("non-empty inputs"));
    }
    let witness_encoded = if reader.peek()? == 1 {
        let flag = reader.u8()?;
        if flag != 1 {
            return Err(ApprovalError::MalformedM6("witness flag"));
        }
        if reader.compact_size()? != 0 {
            return Err(ApprovalError::MalformedM6("non-empty inputs"));
        }
        true
    } else {
        false
    };

    if reader.compact_size()? != 4 {
        return Err(ApprovalError::MalformedM6("output count"));
    }
    let mut outputs = Vec::with_capacity(4);
    for _ in 0..4 {
        let value = reader.u64_le()?;
        if value > i64::MAX as u64 {
            return Err(ApprovalError::MalformedM6("negative output value"));
        }
        let script_len = reader.compact_size()?;
        if script_len > MAX_SCRIPT_BYTES as u64 {
            return Err(ApprovalError::MalformedM6("script size"));
        }
        let script_len =
            usize::try_from(script_len).map_err(|_| ApprovalError::MalformedM6("script size"))?;
        outputs.push(TxOutput {
            value,
            script: reader.take(script_len)?.to_vec(),
        });
    }
    if reader.u32_le()? != 0 {
        return Err(ApprovalError::MalformedM6("lock time"));
    }
    reader.finish()?;

    let outputs: [TxOutput; 4] = outputs
        .try_into()
        .map_err(|_| ApprovalError::MalformedM6("output count"))?;
    let no_witness = serialize_m6_outputs(&outputs, false);
    let canonical_wire = if witness_encoded {
        serialize_m6_outputs(&outputs, true)
    } else {
        no_witness.clone()
    };
    if bytes != canonical_wire {
        return Err(ApprovalError::MalformedM6("non-canonical serialization"));
    }

    Ok(ParsedM6 {
        outputs,
        m6id: bitcoin_double_sha256(&no_witness),
    })
}

#[cfg(feature = "legacy-pxst-reference")]
fn authenticate_legacy_m6(
    m6: &ParsedM6,
    policy: &LegacyM6PolicyV1,
    withdrawal_commitment: Hash32,
) -> Result<(), ApprovalError> {
    let mut expected_fee_script = Vec::with_capacity(10);
    expected_fee_script.extend_from_slice(&[0x6a, 0x08]);
    expected_fee_script.extend_from_slice(&policy.expected_mainchain_fee_sats.to_be_bytes());
    if m6.outputs[0].value != 0 || m6.outputs[0].script != expected_fee_script {
        return Err(ApprovalError::LegacyM6Mismatch("fee output"));
    }

    let mut expected_commitment_script = Vec::with_capacity(34);
    expected_commitment_script.extend_from_slice(&[0x6a, 0x20]);
    expected_commitment_script.extend_from_slice(&withdrawal_commitment);
    if m6.outputs[1].value != 0 || m6.outputs[1].script != expected_commitment_script {
        return Err(ApprovalError::LegacyM6Mismatch(
            "withdrawal commitment output",
        ));
    }

    if m6.outputs[2].value != policy.expected_payout_sats
        || m6.outputs[2].script != policy.expected_payout_script
    {
        return Err(ApprovalError::LegacyM6Mismatch("payout output"));
    }
    if m6.outputs[3].value != 0 {
        return Err(ApprovalError::LegacyM6Mismatch("PXST output value"));
    }
    Ok(())
}

#[cfg(feature = "legacy-pxst-reference")]
fn serialize_m6_outputs(outputs: &[TxOutput; 4], witness_encoded: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&2_i32.to_le_bytes());
    if witness_encoded {
        bytes.extend_from_slice(&[0, 1]);
    }
    bytes.push(0); // zero inputs
    bytes.push(4); // four outputs
    for output in outputs {
        bytes.extend_from_slice(&output.value.to_le_bytes());
        put_compact_size(&mut bytes, output.script.len() as u64);
        bytes.extend_from_slice(&output.script);
    }
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes
}

#[cfg(feature = "legacy-pxst-reference")]
fn put_compact_size(bytes: &mut Vec<u8>, value: u64) {
    if value < 0xfd {
        bytes.push(value as u8);
    } else if value <= u16::MAX as u64 {
        bytes.push(0xfd);
        bytes.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= u32::MAX as u64 {
        bytes.push(0xfe);
        bytes.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        bytes.push(0xff);
        bytes.extend_from_slice(&value.to_le_bytes());
    }
}

#[cfg(feature = "legacy-pxst-reference")]
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

#[cfg(feature = "legacy-pxst-reference")]
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], ApprovalError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(ApprovalError::UnexpectedEnd)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ApprovalError::UnexpectedEnd)?;
        self.offset = end;
        Ok(value)
    }

    fn peek(&self) -> Result<u8, ApprovalError> {
        self.bytes
            .get(self.offset)
            .copied()
            .ok_or(ApprovalError::UnexpectedEnd)
    }

    fn u8(&mut self) -> Result<u8, ApprovalError> {
        Ok(self.take(1)?[0])
    }

    fn i32_le(&mut self) -> Result<i32, ApprovalError> {
        Ok(i32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| ApprovalError::UnexpectedEnd)?,
        ))
    }

    fn u32_le(&mut self) -> Result<u32, ApprovalError> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| ApprovalError::UnexpectedEnd)?,
        ))
    }

    fn u64_le(&mut self) -> Result<u64, ApprovalError> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| ApprovalError::UnexpectedEnd)?,
        ))
    }

    fn compact_size(&mut self) -> Result<u64, ApprovalError> {
        match self.u8()? {
            value @ 0..=0xfc => Ok(u64::from(value)),
            0xfd => {
                let value = u16::from_le_bytes(
                    self.take(2)?
                        .try_into()
                        .map_err(|_| ApprovalError::UnexpectedEnd)?,
                );
                if value < 0xfd {
                    return Err(ApprovalError::NonCanonicalCompactSize);
                }
                Ok(u64::from(value))
            }
            0xfe => {
                let value = u32::from_le_bytes(
                    self.take(4)?
                        .try_into()
                        .map_err(|_| ApprovalError::UnexpectedEnd)?,
                );
                if value <= u16::MAX as u32 {
                    return Err(ApprovalError::NonCanonicalCompactSize);
                }
                Ok(u64::from(value))
            }
            0xff => {
                let value = u64::from_le_bytes(
                    self.take(8)?
                        .try_into()
                        .map_err(|_| ApprovalError::UnexpectedEnd)?,
                );
                if value <= u32::MAX as u64 {
                    return Err(ApprovalError::NonCanonicalCompactSize);
                }
                Ok(value)
            }
        }
    }

    fn finish(self) -> Result<(), ApprovalError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(ApprovalError::MalformedM6("trailing bytes"))
        }
    }
}
