//! Network-agnostic, all-256-slot BIP300/301 replay.
//!
//! This module ports the generic state machine reviewed in
//! `ekulkisnek/USDD@a0a72d1` without its slot-24/USDD classification wrapper.
//! The expected Bitcoin genesis is explicit state, so the same relation can be
//! instantiated for any reviewed network without changing program code.
//! The uniform v2 parameters cannot describe live Alpha. Its separately
//! versioned, fixed policy is in [`alpha_bip300_v3`]; never relabel a v2
//! commitment as an Alpha state commitment.

#[path = "alpha_bip300_v3.rs"]
pub mod alpha_bip300_v3;

use bitcoin::hashes::{sha256d, Hash as _};
use bitcoin::{Block, BlockHash, OutPoint, ScriptBuf, Transaction, Txid};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const M1_TAG: [u8; 4] = [0xd5, 0xe0, 0xc4, 0xaf];
const M2_TAG: [u8; 4] = [0xd6, 0xe1, 0xc5, 0xdf];
const M3_TAG: [u8; 4] = [0xd4, 0x5a, 0xa9, 0x43];
const M4_TAG: [u8; 4] = [0xd7, 0x7d, 0x17, 0x76];
const M7_TAG: [u8; 4] = [0xd1, 0x61, 0x73, 0x68];

/// Exact short-window profile reviewed in `ekulkisnek/USDD@a0a72d1`.
pub const BIP300_REVIEWED_SHORT_NETWORK_PARAMETERS_V2: Bip300ConsensusParametersV2 =
    Bip300ConsensusParametersV2 {
        proposal_max_age: 10,
        proposal_activation_threshold: 5,
        withdrawal_max_age: 10,
        withdrawal_inclusion_threshold: 5,
    };
pub const BIP300_MAX_MONEY_SATOSHIS_V2: u64 = 21_000_000 * 100_000_000;
/// A 4,000,000-weight coinbase cannot contain more outputs than this.
pub const BIP300_MAX_COINBASE_OUTPUTS_V2: usize = 111_111;
pub const BIP300_MAX_PENDING_PROPOSALS_V2: usize = BIP300_MAX_COINBASE_OUTPUTS_V2 * 12;
pub const BIP300_MAX_PENDING_M6IDS_V2: usize = BIP300_MAX_COINBASE_OUTPUTS_V2 * 12;

/// Private dispatch: a block witness cannot choose a policy. The v2 public
/// entry points retain their original uniform policy and commitment encoding.
#[derive(Clone, Copy)]
enum ReplayPolicy {
    UniformV2,
    AlphaV3,
}

impl ReplayPolicy {
    fn proposal_parameters(self, state: &Bip300AllSlotStateV2, slot: u8) -> (u32, u16) {
        match self {
            Self::UniformV2 => (
                state.consensus_parameters.proposal_max_age,
                state.consensus_parameters.proposal_activation_threshold,
            ),
            Self::AlphaV3 if state.active_slots.contains_key(&slot) => (
                alpha_bip300_v3::ALPHA_USED_PROPOSAL_MAX_AGE_V3,
                alpha_bip300_v3::ALPHA_USED_PROPOSAL_THRESHOLD_V3,
            ),
            Self::AlphaV3 => (
                alpha_bip300_v3::ALPHA_UNUSED_PROPOSAL_MAX_AGE_V3,
                alpha_bip300_v3::ALPHA_UNUSED_PROPOSAL_THRESHOLD_V3,
            ),
        }
    }

    fn max_pending_proposals(self) -> usize {
        match self {
            Self::UniformV2 => BIP300_MAX_PENDING_PROPOSALS_V2,
            Self::AlphaV3 => alpha_bip300_v3::ALPHA_MAX_PENDING_PROPOSALS_V3,
        }
    }

    fn max_pending_m6ids(self) -> usize {
        match self {
            Self::UniformV2 => BIP300_MAX_PENDING_M6IDS_V2,
            Self::AlphaV3 => alpha_bip300_v3::ALPHA_MAX_PENDING_M6IDS_V3,
        }
    }

    fn enabled(self, height: u32) -> bool {
        match self {
            Self::UniformV2 => true,
            Self::AlphaV3 => height >= alpha_bip300_v3::ALPHA_BIP300_ACTIVATION_HEIGHT_V3,
        }
    }

    fn enforces_unique_m8_slot(self) -> bool {
        matches!(self, Self::AlphaV3)
    }
}

/// Network consensus values are committed state rather than program constants.
/// This keeps the relation network-agnostic without silently applying Signet
/// or test-network voting windows to another Bitcoin network.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bip300ConsensusParametersV2 {
    pub proposal_max_age: u32,
    pub proposal_activation_threshold: u16,
    pub withdrawal_max_age: u32,
    pub withdrawal_inclusion_threshold: u16,
}

impl Bip300ConsensusParametersV2 {
    pub fn validate(self) -> Result<(), Bip300ReplayErrorV2> {
        if self.proposal_max_age == 0
            || self.withdrawal_max_age == 0
            || self.proposal_activation_threshold == 0
            || self.withdrawal_inclusion_threshold == 0
            || u32::from(self.proposal_activation_threshold) > self.proposal_max_age
            || u32::from(self.withdrawal_inclusion_threshold) > self.withdrawal_max_age
        {
            return Err(Bip300ReplayErrorV2::InvalidConsensusParameters);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bip300ProposalV2 {
    pub slot: u8,
    pub proposal_hash: [u8; 32],
    pub proposal_height: u32,
    pub votes: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bip300PendingM6idV2 {
    pub m6id: Txid,
    pub proposal_height: u32,
    pub score: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bip300CtipV2 {
    pub outpoint: OutPoint,
    pub value_sat: u64,
    pub sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Bip300EffectiveM4ActionV2 {
    Upvote { m6id: Txid },
    Alarm,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bip300ActiveSlotV2 {
    pub proposal_hash: [u8; 32],
    pub activation_height: u32,
    pub ctip: Option<Bip300CtipV2>,
    pub next_treasury_sequence: u64,
    pub pending_m6ids: Vec<Bip300PendingM6idV2>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bip300AllSlotStateV2 {
    /// Frozen by the proof configuration, not selected by a block witness.
    pub network_genesis: BlockHash,
    /// Frozen alongside the genesis; never inferred from a network name.
    pub consensus_parameters: Bip300ConsensusParametersV2,
    pub next_height: u32,
    pub tip_hash: Option<BlockHash>,
    pub proposals: BTreeMap<(u8, [u8; 32]), Bip300ProposalV2>,
    pub active_slots: BTreeMap<u8, Bip300ActiveSlotV2>,
    pub previous_effective_m4: BTreeMap<u8, Bip300EffectiveM4ActionV2>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bip300ActivationV2 {
    pub slot: u8,
    pub proposal_hash: [u8; 32],
    pub block_height: u32,
    pub replaced_existing: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bip300EffectiveM4V2 {
    pub slot: u8,
    pub action: Bip300EffectiveM4ActionV2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bip300BmmCommitmentV2 {
    pub slot: u8,
    pub child_hash: BlockHash,
    pub coinbase_vout: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bip300DepositV2 {
    pub slot: u8,
    /// Treasury immediately before this transaction, not before the block.
    /// None denotes the first treasury output for an activated slot.
    pub prior_ctip: Option<Bip300CtipV2>,
    pub outpoint: Bip300CtipV2,
    pub block_hash: BlockHash,
    pub block_height: u32,
    pub value_sat: u64,
    pub address: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bip300ApprovedM6V2 {
    pub slot: u8,
    pub m6id: Txid,
    pub transaction_id: Txid,
    pub block_hash: BlockHash,
    pub block_height: u32,
    pub sequence: u64,
    pub successor_ctip: Bip300CtipV2,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Bip300CoinbaseEffectsV2 {
    pub activations: Vec<Bip300ActivationV2>,
    pub effective_m4: Vec<Bip300EffectiveM4V2>,
    pub expired_m6ids: Vec<(u8, Txid)>,
    pub bmm_commitments: Vec<Bip300BmmCommitmentV2>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Bip300BlockEffectsV2 {
    pub activations: Vec<Bip300ActivationV2>,
    pub deposits: Vec<Bip300DepositV2>,
    pub successful_m6s: Vec<Bip300ApprovedM6V2>,
    pub effective_m4: Vec<Bip300EffectiveM4V2>,
    pub expired_m6ids: Vec<(u8, Txid)>,
    pub bmm_commitments: Vec<Bip300BmmCommitmentV2>,
    pub matching_m8_requests: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum Bip300ReplayErrorV2 {
    #[error("network genesis is zero")]
    ZeroGenesis,
    #[error("BIP300 consensus parameters are invalid")]
    InvalidConsensusParameters,
    #[error("BIP300 state is noncanonical")]
    MalformedState,
    #[error("pending proposal bound exceeded")]
    PendingProposalLimitExceeded,
    #[error("pending M6id bound exceeded")]
    PendingM6idLimitExceeded,
    #[error("duplicate M1 message")]
    DuplicateM1,
    #[error("duplicate M2 slot")]
    DuplicateM2,
    #[error("duplicate M4 message")]
    DuplicateM4,
    #[error("duplicate M7 slot")]
    DuplicateM7,
    #[error("M3 targets an inactive slot")]
    M3ForInactiveSlot,
    #[error("M3 bundle is already pending")]
    M3BundleAlreadyPending,
    #[error("M4 vote count is invalid")]
    M4InvalidVoteCount,
    #[error("M4 upvote references no pending bundle")]
    M4UpvoteMissingBundle,
    #[error("two-byte M4 encoding was unnecessary")]
    M4TwoBytesWithinByteRange,
    #[error("M4 repeat references an expired bundle")]
    M4RepeatMissingBundle,
    #[error("vote arithmetic overflow")]
    VoteOverflow,
    #[error("proposal height is ahead of the block")]
    ProposalHeightAhead,
    #[error("proposal votes exceed its age")]
    ProposalVotesAhead,
    #[error("coinbase output index exceeds u32")]
    OutputIndexOverflow,
    #[error("candidate block is empty or does not link to the replay state")]
    BrokenParentLink,
    #[error("first replayed block is not the configured network genesis")]
    WrongGenesis,
    #[error("M8 has no matching same-block M7")]
    M8WithoutMatchingM7,
    #[error("M8 child hash differs from its M7")]
    M8WrongChildHash,
    #[error("M8 commits a parent other than the candidate block parent")]
    M8Expired,
    #[error("multiple valid M8 requests exist for one sidechain slot")]
    DuplicateM8Slot,
    #[error("M8 count overflow")]
    M8CountOverflow,
    #[error("multiple treasury outputs exist for one slot")]
    MultipleTreasuryOutputs,
    #[error("a prior CTIP was spent without an exact successor")]
    TreasurySpentWithoutReplacement,
    #[error("a new treasury output did not spend the prior CTIP")]
    OldCtipUnspent,
    #[error("a treasury transition has zero value delta")]
    ZeroCtipDelta,
    #[error("a transaction ambiguously combines M5 and M6 or multiple M6s")]
    AmbiguousM5M6,
    #[error("M6 does not have exactly one input")]
    M6InputCount,
    #[error("M6 successor CTIP is not output zero")]
    M6TreasuryOutputIndex,
    #[error("M6 amount arithmetic overflow or underflow")]
    M6AmountOverflow,
    #[error("M6id is not pending for its slot")]
    M6MissingPendingBundle,
    #[error("M6 score has not crossed the inclusion threshold")]
    M6InsufficientScore,
    #[error("M5 is missing its immediately following address output")]
    MissingDepositAddress,
    #[error("treasury sequence or amount arithmetic overflow")]
    AmountOverflow,
    #[error("canonical BIP300 state encoding length overflow")]
    CanonicalLengthOverflow,
}

impl Bip300AllSlotStateV2 {
    pub fn before_genesis(
        network_genesis: BlockHash,
        consensus_parameters: Bip300ConsensusParametersV2,
    ) -> Result<Self, Bip300ReplayErrorV2> {
        if network_genesis == BlockHash::all_zeros() {
            return Err(Bip300ReplayErrorV2::ZeroGenesis);
        }
        consensus_parameters.validate()?;
        Ok(Self {
            network_genesis,
            consensus_parameters,
            next_height: 0,
            tip_hash: None,
            proposals: BTreeMap::new(),
            active_slots: BTreeMap::new(),
            previous_effective_m4: BTreeMap::new(),
        })
    }

    pub fn validate(&self) -> Result<(), Bip300ReplayErrorV2> {
        self.validate_with_policy(ReplayPolicy::UniformV2)
    }

    fn validate_with_policy(&self, policy: ReplayPolicy) -> Result<(), Bip300ReplayErrorV2> {
        if let ReplayPolicy::AlphaV3 = policy {
            alpha_bip300_v3::validate_fixed_alpha_state(self)?;
        }
        if self.network_genesis == BlockHash::all_zeros()
            || (self.next_height == 0) != self.tip_hash.is_none()
        {
            return Err(Bip300ReplayErrorV2::MalformedState);
        }
        self.consensus_parameters.validate()?;
        if self.next_height == 0
            && (!self.proposals.is_empty()
                || !self.active_slots.is_empty()
                || !self.previous_effective_m4.is_empty())
        {
            return Err(Bip300ReplayErrorV2::MalformedState);
        }
        if self.proposals.len() > policy.max_pending_proposals() {
            return Err(Bip300ReplayErrorV2::PendingProposalLimitExceeded);
        }
        let tip_height = self.next_height.saturating_sub(1);
        for (key, proposal) in &self.proposals {
            if *key != (proposal.slot, proposal.proposal_hash)
                || proposal.proposal_height > tip_height
                || u32::from(proposal.votes) > tip_height.saturating_sub(proposal.proposal_height)
            {
                return Err(Bip300ReplayErrorV2::MalformedState);
            }
        }
        let mut total_pending = 0usize;
        let mut seen_ctips = BTreeSet::new();
        for active in self.active_slots.values() {
            if active.activation_height > tip_height {
                return Err(Bip300ReplayErrorV2::MalformedState);
            }
            if let Some(ctip) = active.ctip {
                if ctip.value_sat > BIP300_MAX_MONEY_SATOSHIS_V2
                    || ctip.sequence >= active.next_treasury_sequence
                    || !seen_ctips.insert(ctip.outpoint)
                {
                    return Err(Bip300ReplayErrorV2::MalformedState);
                }
            } else if active.next_treasury_sequence != 0 {
                return Err(Bip300ReplayErrorV2::MalformedState);
            }
            total_pending = total_pending
                .checked_add(active.pending_m6ids.len())
                .ok_or(Bip300ReplayErrorV2::PendingM6idLimitExceeded)?;
            let mut seen = BTreeSet::new();
            for pending in &active.pending_m6ids {
                if !seen.insert(pending.m6id)
                    || pending.proposal_height > tip_height
                    || tip_height.saturating_sub(pending.proposal_height)
                        > self.consensus_parameters.withdrawal_max_age
                {
                    return Err(Bip300ReplayErrorV2::MalformedState);
                }
            }
        }
        if total_pending > policy.max_pending_m6ids()
            || self
                .previous_effective_m4
                .keys()
                .any(|slot| !self.active_slots.contains_key(slot))
        {
            return Err(Bip300ReplayErrorV2::MalformedState);
        }
        Ok(())
    }

    /// Exact network-bound replay commitment used by the recursive relation.
    pub fn commitment(&self) -> Result<[u8; 32], Bip300ReplayErrorV2> {
        self.commitment_with_policy(ReplayPolicy::UniformV2)
    }

    fn commitment_with_policy(
        &self,
        policy: ReplayPolicy,
    ) -> Result<[u8; 32], Bip300ReplayErrorV2> {
        self.validate_with_policy(policy)?;
        let mut bytes = Vec::new();
        bytes.push(2);
        bytes.extend_from_slice(self.network_genesis.as_byte_array());
        bytes.extend_from_slice(&self.consensus_parameters.proposal_max_age.to_be_bytes());
        bytes.extend_from_slice(
            &self
                .consensus_parameters
                .proposal_activation_threshold
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&self.consensus_parameters.withdrawal_max_age.to_be_bytes());
        bytes.extend_from_slice(
            &self
                .consensus_parameters
                .withdrawal_inclusion_threshold
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&self.next_height.to_be_bytes());
        match self.tip_hash {
            None => bytes.push(0),
            Some(tip) => {
                bytes.push(1);
                bytes.extend_from_slice(tip.as_byte_array());
            }
        }
        bytes.extend_from_slice(
            &u32::try_from(self.proposals.len())
                .map_err(|_| Bip300ReplayErrorV2::CanonicalLengthOverflow)?
                .to_be_bytes(),
        );
        for proposal in self.proposals.values() {
            bytes.push(proposal.slot);
            bytes.extend_from_slice(&proposal.proposal_hash);
            bytes.extend_from_slice(&proposal.proposal_height.to_be_bytes());
            bytes.extend_from_slice(&proposal.votes.to_be_bytes());
        }
        bytes.extend_from_slice(
            &u16::try_from(self.active_slots.len())
                .map_err(|_| Bip300ReplayErrorV2::CanonicalLengthOverflow)?
                .to_be_bytes(),
        );
        for (slot, active) in &self.active_slots {
            bytes.push(*slot);
            bytes.extend_from_slice(&active.proposal_hash);
            bytes.extend_from_slice(&active.activation_height.to_be_bytes());
            match active.ctip {
                None => bytes.push(0),
                Some(ctip) => {
                    bytes.push(1);
                    bytes.extend_from_slice(ctip.outpoint.txid.as_byte_array());
                    bytes.extend_from_slice(&ctip.outpoint.vout.to_be_bytes());
                    bytes.extend_from_slice(&ctip.value_sat.to_be_bytes());
                    bytes.extend_from_slice(&ctip.sequence.to_be_bytes());
                }
            }
            bytes.extend_from_slice(&active.next_treasury_sequence.to_be_bytes());
            bytes.extend_from_slice(
                &u32::try_from(active.pending_m6ids.len())
                    .map_err(|_| Bip300ReplayErrorV2::CanonicalLengthOverflow)?
                    .to_be_bytes(),
            );
            for pending in &active.pending_m6ids {
                bytes.extend_from_slice(pending.m6id.as_byte_array());
                bytes.extend_from_slice(&pending.proposal_height.to_be_bytes());
                bytes.extend_from_slice(&pending.score.to_be_bytes());
            }
        }
        bytes.extend_from_slice(
            &u16::try_from(self.previous_effective_m4.len())
                .map_err(|_| Bip300ReplayErrorV2::CanonicalLengthOverflow)?
                .to_be_bytes(),
        );
        for (slot, action) in &self.previous_effective_m4 {
            bytes.push(*slot);
            match action {
                Bip300EffectiveM4ActionV2::Alarm => bytes.push(0),
                Bip300EffectiveM4ActionV2::Upvote { m6id } => {
                    bytes.push(1);
                    bytes.extend_from_slice(m6id.as_byte_array());
                }
            }
        }
        let mut preimage = b"ECX/full-bitcoin/bip300-all-slot-state/v2-network-parameters".to_vec();
        preimage.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        preimage.extend_from_slice(&bytes);
        Ok(crate::sha256_bytes(&preimage))
    }
}

#[derive(Clone, Copy)]
enum ParentMessageV2 {
    M1 { slot: u8, proposal_hash: [u8; 32] },
    M2 { slot: u8, proposal_hash: [u8; 32] },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum M4MessageV2 {
    RepeatPrevious,
    OneByte(Vec<u8>),
    TwoBytes(Vec<u16>),
    LeadingBy50,
}

fn single_op_return_push(script: &ScriptBuf) -> Option<&[u8]> {
    let bytes = script.as_bytes();
    if bytes.first().copied() != Some(0x6a) {
        return None;
    }
    let mut cursor = 1usize;
    let opcode = *bytes.get(cursor)?;
    cursor += 1;
    let length = match opcode {
        0..=75 => usize::from(opcode),
        0x4c => {
            let length = usize::from(*bytes.get(cursor)?);
            cursor += 1;
            length
        }
        0x4d => {
            let raw = bytes.get(cursor..cursor + 2)?;
            cursor += 2;
            usize::from(u16::from_le_bytes([raw[0], raw[1]]))
        }
        0x4e => {
            let raw = bytes.get(cursor..cursor + 4)?;
            cursor += 4;
            usize::try_from(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]])).ok()?
        }
        _ => return None,
    };
    let payload = bytes.get(cursor..cursor.checked_add(length)?)?;
    (cursor + length == bytes.len()).then_some(payload)
}

fn parse_parent_message(script: &ScriptBuf) -> Option<ParentMessageV2> {
    let payload = single_op_return_push(script)?;
    if payload.len() < 5 {
        return None;
    }
    if payload[..4] == M1_TAG {
        return Some(ParentMessageV2::M1 {
            slot: payload[4],
            proposal_hash: sha256d::Hash::hash(&payload[5..]).to_byte_array(),
        });
    }
    if payload.len() == 37 && payload[..4] == M2_TAG {
        let mut proposal_hash = [0; 32];
        proposal_hash.copy_from_slice(&payload[5..]);
        return Some(ParentMessageV2::M2 {
            slot: payload[4],
            proposal_hash,
        });
    }
    None
}

fn parse_m3(script: &ScriptBuf) -> Option<(u8, Txid)> {
    let payload = single_op_return_push(script)?;
    if payload.len() != 37 || payload[..4] != M3_TAG {
        return None;
    }
    let mut display = [0u8; 32];
    display.copy_from_slice(&payload[5..]);
    display.reverse();
    Some((payload[4], Txid::from_byte_array(display)))
}

fn parse_m4(script: &ScriptBuf) -> Option<M4MessageV2> {
    let payload = single_op_return_push(script)?;
    if payload.len() < 5 || payload[..4] != M4_TAG {
        return None;
    }
    let body = &payload[5..];
    match payload[4] {
        0 if body.is_empty() => Some(M4MessageV2::RepeatPrevious),
        1 => Some(M4MessageV2::OneByte(body.to_vec())),
        2 if body.len() % 2 == 0 => Some(M4MessageV2::TwoBytes(
            body.chunks_exact(2)
                .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
                .collect(),
        )),
        3 if body.is_empty() => Some(M4MessageV2::LeadingBy50),
        _ => None,
    }
}

fn parse_m7(script: &ScriptBuf) -> Option<(u8, BlockHash)> {
    let payload = single_op_return_push(script)?;
    if payload.len() != 37 || payload[..4] != M7_TAG {
        return None;
    }
    let mut hash = [0; 32];
    hash.copy_from_slice(&payload[5..]);
    Some((payload[4], BlockHash::from_byte_array(hash)))
}

fn apply_upvote(
    active: &mut Bip300ActiveSlotV2,
    index: usize,
) -> Result<Option<Bip300EffectiveM4ActionV2>, Bip300ReplayErrorV2> {
    let target = active
        .pending_m6ids
        .get(index)
        .copied()
        .ok_or(Bip300ReplayErrorV2::M4UpvoteMissingBundle)?;
    if target.score == u16::MAX {
        return Ok(None);
    }
    for (candidate_index, pending) in active.pending_m6ids.iter_mut().enumerate() {
        if candidate_index == index {
            pending.score = pending
                .score
                .checked_add(1)
                .ok_or(Bip300ReplayErrorV2::VoteOverflow)?;
        } else {
            pending.score = pending.score.saturating_sub(1);
        }
    }
    Ok(Some(Bip300EffectiveM4ActionV2::Upvote {
        m6id: target.m6id,
    }))
}

fn apply_alarm(active: &mut Bip300ActiveSlotV2) -> Option<Bip300EffectiveM4ActionV2> {
    let mut changed = false;
    for pending in &mut active.pending_m6ids {
        changed |= pending.score != 0;
        pending.score = pending.score.saturating_sub(1);
    }
    changed.then_some(Bip300EffectiveM4ActionV2::Alarm)
}

fn apply_vote(
    active: &mut Bip300ActiveSlotV2,
    vote: u16,
) -> Result<Option<Bip300EffectiveM4ActionV2>, Bip300ReplayErrorV2> {
    match vote {
        0xffff => Ok(None),
        0xfffe => Ok(apply_alarm(active)),
        index => apply_upvote(active, usize::from(index)),
    }
}

fn apply_m4(
    state: &mut Bip300AllSlotStateV2,
    message: &M4MessageV2,
) -> Result<BTreeMap<u8, Bip300EffectiveM4ActionV2>, Bip300ReplayErrorV2> {
    let slots = state.active_slots.keys().copied().collect::<Vec<_>>();
    let mut effective = BTreeMap::new();
    match message {
        M4MessageV2::OneByte(votes) => {
            if votes.len() != slots.len() {
                return Err(Bip300ReplayErrorV2::M4InvalidVoteCount);
            }
            for (slot, vote) in slots.into_iter().zip(votes.iter().copied()) {
                let vote = match vote {
                    0xff => 0xffff,
                    0xfe => 0xfffe,
                    value => u16::from(value),
                };
                if let Some(action) = apply_vote(
                    state.active_slots.get_mut(&slot).expect("active slot"),
                    vote,
                )? {
                    effective.insert(slot, action);
                }
            }
        }
        M4MessageV2::TwoBytes(votes) => {
            if votes.iter().all(|vote| *vote <= 253) {
                return Err(Bip300ReplayErrorV2::M4TwoBytesWithinByteRange);
            }
            if votes.len() != slots.len() {
                return Err(Bip300ReplayErrorV2::M4InvalidVoteCount);
            }
            for (slot, vote) in slots.into_iter().zip(votes.iter().copied()) {
                if let Some(action) = apply_vote(
                    state.active_slots.get_mut(&slot).expect("active slot"),
                    vote,
                )? {
                    effective.insert(slot, action);
                }
            }
        }
        M4MessageV2::LeadingBy50 => {
            for slot in slots {
                let active = state.active_slots.get_mut(&slot).expect("active slot");
                let mut leader = None;
                let mut highest = 0u16;
                let mut second = 0u16;
                for (index, pending) in active.pending_m6ids.iter().enumerate() {
                    if pending.score > highest {
                        second = highest;
                        highest = pending.score;
                        leader = Some(index);
                    } else if pending.score > second {
                        second = pending.score;
                    }
                }
                if highest.saturating_sub(second) >= 50 && highest < u16::MAX {
                    if let Some(action) =
                        apply_upvote(active, leader.expect("positive leader has pending M6id"))?
                    {
                        effective.insert(slot, action);
                    }
                }
            }
        }
        M4MessageV2::RepeatPrevious => {
            for (slot, prior_action) in state.previous_effective_m4.clone() {
                let active = state
                    .active_slots
                    .get_mut(&slot)
                    .ok_or(Bip300ReplayErrorV2::MalformedState)?;
                let action = match prior_action {
                    Bip300EffectiveM4ActionV2::Alarm => apply_alarm(active),
                    Bip300EffectiveM4ActionV2::Upvote { m6id } => {
                        let index = active
                            .pending_m6ids
                            .iter()
                            .position(|pending| pending.m6id == m6id)
                            .ok_or(Bip300ReplayErrorV2::M4RepeatMissingBundle)?;
                        apply_upvote(active, index)?
                    }
                };
                if let Some(action) = action {
                    effective.insert(slot, action);
                }
            }
        }
    }
    Ok(effective)
}

fn activate_slot(
    state: &mut Bip300AllSlotStateV2,
    slot: u8,
    proposal_hash: [u8; 32],
    height: u32,
) -> Bip300ActivationV2 {
    let replaced_existing = state.active_slots.contains_key(&slot);
    state
        .active_slots
        .entry(slot)
        .and_modify(|active| {
            active.proposal_hash = proposal_hash;
            active.activation_height = height;
        })
        .or_insert(Bip300ActiveSlotV2 {
            proposal_hash,
            activation_height: height,
            ctip: None,
            next_treasury_sequence: 0,
            pending_m6ids: Vec::new(),
        });
    Bip300ActivationV2 {
        slot,
        proposal_hash,
        block_height: height,
        replaced_existing,
    }
}

/// Apply all M1/M2/M3/M4/M7 messages in exact coinbase output order.
///
/// The caller passes a candidate clone and installs it only after the complete
/// block, including M5/M6/M8, succeeds. This function itself is atomic.
pub fn apply_bip300_coinbase_messages_v2(
    state: &Bip300AllSlotStateV2,
    height: u32,
    output_scripts: &[ScriptBuf],
) -> Result<(Bip300AllSlotStateV2, Bip300CoinbaseEffectsV2), Bip300ReplayErrorV2> {
    apply_bip300_coinbase_with_policy(state, height, output_scripts, ReplayPolicy::UniformV2)
}

fn apply_bip300_coinbase_with_policy(
    state: &Bip300AllSlotStateV2,
    height: u32,
    output_scripts: &[ScriptBuf],
    policy: ReplayPolicy,
) -> Result<(Bip300AllSlotStateV2, Bip300CoinbaseEffectsV2), Bip300ReplayErrorV2> {
    state.validate_with_policy(policy)?;
    if height != state.next_height || output_scripts.len() > BIP300_MAX_COINBASE_OUTPUTS_V2 {
        return Err(Bip300ReplayErrorV2::MalformedState);
    }
    if !policy.enabled(height) {
        return Ok((state.clone(), Bip300CoinbaseEffectsV2::default()));
    }
    let mut next = state.clone();
    let mut m1s = BTreeSet::new();
    let mut m2_slots = BTreeSet::new();
    let mut saw_m4 = false;
    let mut m7_slots = BTreeSet::new();
    let mut effects = Bip300CoinbaseEffectsV2::default();
    let mut current_effective_m4 = BTreeMap::new();

    for (vout, script) in output_scripts.iter().enumerate() {
        match parse_parent_message(script) {
            Some(ParentMessageV2::M1 {
                slot,
                proposal_hash,
            }) => {
                if !m1s.insert((slot, proposal_hash)) {
                    return Err(Bip300ReplayErrorV2::DuplicateM1);
                }
                let id = (slot, proposal_hash);
                if !next.proposals.contains_key(&id) {
                    if next.proposals.len() == policy.max_pending_proposals() {
                        return Err(Bip300ReplayErrorV2::PendingProposalLimitExceeded);
                    }
                    next.proposals.insert(
                        id,
                        Bip300ProposalV2 {
                            slot,
                            proposal_hash,
                            proposal_height: height,
                            votes: 0,
                        },
                    );
                }
            }
            Some(ParentMessageV2::M2 {
                slot,
                proposal_hash,
            }) => {
                if !m2_slots.insert(slot) {
                    return Err(Bip300ReplayErrorV2::DuplicateM2);
                }
                let id = (slot, proposal_hash);
                let Some(mut proposal) = next.proposals.get(&id).copied() else {
                    continue;
                };
                if proposal.proposal_height == height {
                    continue;
                }
                proposal.votes = proposal
                    .votes
                    .checked_add(1)
                    .ok_or(Bip300ReplayErrorV2::VoteOverflow)?;
                let age = height.saturating_sub(proposal.proposal_height);
                let (maximum_age, threshold) = policy.proposal_parameters(&next, slot);
                if proposal.votes > threshold && age <= maximum_age {
                    next.proposals.remove(&id);
                    effects
                        .activations
                        .push(activate_slot(&mut next, slot, proposal_hash, height));
                } else {
                    next.proposals.insert(id, proposal);
                }
            }
            None => {}
        }

        if let Some((slot, m6id)) = parse_m3(script) {
            let total_pending = next
                .active_slots
                .values()
                .map(|active| active.pending_m6ids.len())
                .try_fold(0usize, |sum, count| sum.checked_add(count))
                .ok_or(Bip300ReplayErrorV2::PendingM6idLimitExceeded)?;
            let active = next
                .active_slots
                .get_mut(&slot)
                .ok_or(Bip300ReplayErrorV2::M3ForInactiveSlot)?;
            if active.pending_m6ids.iter().any(|item| item.m6id == m6id) {
                return Err(Bip300ReplayErrorV2::M3BundleAlreadyPending);
            }
            if total_pending == policy.max_pending_m6ids() {
                return Err(Bip300ReplayErrorV2::PendingM6idLimitExceeded);
            }
            active.pending_m6ids.push(Bip300PendingM6idV2 {
                m6id,
                proposal_height: height,
                score: 1,
            });
        }

        if let Some(message) = parse_m4(script) {
            if saw_m4 {
                return Err(Bip300ReplayErrorV2::DuplicateM4);
            }
            saw_m4 = true;
            current_effective_m4 = apply_m4(&mut next, &message)?;
        }

        if let Some((slot, child_hash)) = parse_m7(script) {
            if !m7_slots.insert(slot) {
                return Err(Bip300ReplayErrorV2::DuplicateM7);
            }
            effects.bmm_commitments.push(Bip300BmmCommitmentV2 {
                slot,
                child_hash,
                coinbase_vout: u32::try_from(vout)
                    .map_err(|_| Bip300ReplayErrorV2::OutputIndexOverflow)?,
            });
        }
    }

    next.previous_effective_m4 = current_effective_m4.clone();
    effects.effective_m4 = current_effective_m4
        .into_iter()
        .map(|(slot, action)| Bip300EffectiveM4V2 { slot, action })
        .collect();

    let mut failed_proposals = Vec::new();
    for (id, proposal) in &next.proposals {
        let age = height
            .checked_sub(proposal.proposal_height)
            .ok_or(Bip300ReplayErrorV2::ProposalHeightAhead)?;
        if u32::from(proposal.votes) > age {
            return Err(Bip300ReplayErrorV2::ProposalVotesAhead);
        }
        // Resolve occupancy after all ordered M2 transitions, just as the
        // enforcer's failure pass reads its current active-sidechain table.
        let (maximum_age, threshold) = policy.proposal_parameters(&next, proposal.slot);
        let maximum_failures = maximum_age - u32::from(threshold);
        let failures = age - u32::from(proposal.votes);
        if age > maximum_age || (age > maximum_failures && failures >= maximum_failures) {
            failed_proposals.push(*id);
        }
    }
    for id in failed_proposals {
        next.proposals.remove(&id);
    }

    for (slot, active) in &mut next.active_slots {
        active.pending_m6ids.retain(|pending| {
            let live = height.saturating_sub(pending.proposal_height)
                <= next.consensus_parameters.withdrawal_max_age;
            if !live {
                effects.expired_m6ids.push((*slot, pending.m6id));
            }
            live
        });
    }
    Ok((next, effects))
}

const M8_TAG: [u8; 3] = [0x00, 0xbf, 0x00];
const OP_DRIVECHAIN: u8 = 0xb4;

fn treasury_slot(script: &ScriptBuf) -> Option<u8> {
    let bytes = script.as_bytes();
    if bytes.len() == 4 && bytes[0] == OP_DRIVECHAIN && bytes[1] == 1 && bytes[3] == 0x51 {
        Some(bytes[2])
    } else {
        None
    }
}

fn parse_m8(transaction: &Transaction) -> Option<(u8, BlockHash, BlockHash)> {
    let script = transaction.output.first()?.script_pubkey.as_bytes();
    if script.len() != 70 || script[0] != 0x6a || script[1] != 68 || script[2..5] != M8_TAG {
        return None;
    }
    let mut child = [0; 32];
    child.copy_from_slice(&script[6..38]);
    let mut previous = [0; 32];
    previous.copy_from_slice(&script[38..70]);
    Some((
        script[5],
        BlockHash::from_byte_array(child),
        BlockHash::from_byte_array(previous),
    ))
}

fn encode_compact_size(value: usize, output: &mut Vec<u8>) {
    if value < 253 {
        output.push(value as u8);
    } else if value <= u16::MAX as usize {
        output.push(253);
        output.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= u32::MAX as usize {
        output.push(254);
        output.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        output.push(255);
        output.extend_from_slice(&(value as u64).to_le_bytes());
    }
}

fn generic_m6id(
    transaction: &Transaction,
    old_value: u64,
    new_value: u64,
) -> Result<Txid, Bip300ReplayErrorV2> {
    let payout_total = transaction
        .output
        .iter()
        .skip(1)
        .try_fold(0u64, |sum, output| {
            sum.checked_add(output.value.to_sat())
                .ok_or(Bip300ReplayErrorV2::M6AmountOverflow)
        })?;
    let total_outputs = new_value
        .checked_add(payout_total)
        .ok_or(Bip300ReplayErrorV2::M6AmountOverflow)?;
    let fee = old_value
        .checked_sub(total_outputs)
        .ok_or(Bip300ReplayErrorV2::M6AmountOverflow)?;

    // Enforcer compute_m6id: remove the sole input, blind output zero to an
    // OP_RETURN carrying the big-endian fee, preserve every payout, version,
    // and locktime, then hash the non-witness serialization.
    let mut blinded = Vec::new();
    blinded.extend_from_slice(&transaction.version.0.to_le_bytes());
    blinded.push(0);
    encode_compact_size(transaction.output.len(), &mut blinded);
    blinded.extend_from_slice(&0u64.to_le_bytes());
    blinded.extend_from_slice(&[10, 0x6a, 8]);
    blinded.extend_from_slice(&fee.to_be_bytes());
    for output in transaction.output.iter().skip(1) {
        blinded.extend_from_slice(&output.value.to_sat().to_le_bytes());
        encode_compact_size(output.script_pubkey.len(), &mut blinded);
        blinded.extend_from_slice(output.script_pubkey.as_bytes());
    }
    blinded.extend_from_slice(&transaction.lock_time.to_consensus_u32().to_le_bytes());
    Ok(Txid::from_byte_array(
        sha256d::Hash::hash(&blinded).to_byte_array(),
    ))
}

fn approve_m6(
    state: &mut Bip300AllSlotStateV2,
    slot: u8,
    transaction: &Transaction,
    old_ctip: Bip300CtipV2,
    new_value: u64,
    block_hash: BlockHash,
    block_height: u32,
) -> Result<Bip300ApprovedM6V2, Bip300ReplayErrorV2> {
    let inclusion_threshold = state.consensus_parameters.withdrawal_inclusion_threshold;
    let m6id = generic_m6id(transaction, old_ctip.value_sat, new_value)?;
    let active = state
        .active_slots
        .get_mut(&slot)
        .ok_or(Bip300ReplayErrorV2::MalformedState)?;
    let index = active
        .pending_m6ids
        .iter()
        .position(|pending| pending.m6id == m6id)
        .ok_or(Bip300ReplayErrorV2::M6MissingPendingBundle)?;
    if active.pending_m6ids[index].score <= inclusion_threshold {
        return Err(Bip300ReplayErrorV2::M6InsufficientScore);
    }
    active.pending_m6ids.remove(index);
    let sequence = active.next_treasury_sequence;
    active.next_treasury_sequence = active
        .next_treasury_sequence
        .checked_add(1)
        .ok_or(Bip300ReplayErrorV2::AmountOverflow)?;
    let successor_ctip = Bip300CtipV2 {
        outpoint: OutPoint {
            txid: transaction.compute_txid(),
            vout: 0,
        },
        value_sat: new_value,
        sequence,
    };
    active.ctip = Some(successor_ctip);
    Ok(Bip300ApprovedM6V2 {
        slot,
        m6id,
        transaction_id: transaction.compute_txid(),
        block_hash,
        block_height,
        sequence,
        successor_ctip,
    })
}

#[derive(Clone, Copy)]
struct NewCtipV2 {
    vout: usize,
    value_sat: u64,
}

fn apply_transactions(
    state: &mut Bip300AllSlotStateV2,
    transactions: &[Transaction],
    height: u32,
    block_hash: BlockHash,
    previous_block: BlockHash,
    bmm: &BTreeMap<u8, BlockHash>,
    policy: ReplayPolicy,
) -> Result<(Vec<Bip300DepositV2>, Vec<Bip300ApprovedM6V2>, u32), Bip300ReplayErrorV2> {
    let mut deposits = Vec::new();
    let mut successful_m6s = Vec::new();
    let mut matching_m8_requests = 0u32;
    let mut accepted_m8_slots = BTreeSet::new();

    for transaction in transactions.iter().skip(1) {
        if let Some((slot, child_hash, previous_hash)) = parse_m8(transaction) {
            let accepted = bmm
                .get(&slot)
                .ok_or(Bip300ReplayErrorV2::M8WithoutMatchingM7)?;
            if *accepted != child_hash {
                return Err(Bip300ReplayErrorV2::M8WrongChildHash);
            }
            if previous_hash != previous_block {
                return Err(Bip300ReplayErrorV2::M8Expired);
            }
            // Frozen native Alpha enforcer 86543d13 accepts at most one M8
            // per block and slot, even if distinct transactions commit the
            // same child. Check after M7/parent binding so invalid requests
            // retain their own rejection. This set is intentionally local to
            // the block, and the separate legacy v2 replay stays unchanged.
            if policy.enforces_unique_m8_slot() && !accepted_m8_slots.insert(slot) {
                return Err(Bip300ReplayErrorV2::DuplicateM8Slot);
            }
            matching_m8_requests = matching_m8_requests
                .checked_add(1)
                .ok_or(Bip300ReplayErrorV2::M8CountOverflow)?;
        }

        let mut spent_ctips = BTreeMap::new();
        for (slot, active) in &state.active_slots {
            let Some(ctip) = active.ctip else {
                continue;
            };
            if transaction
                .input
                .iter()
                .any(|input| input.previous_output == ctip.outpoint)
            {
                spent_ctips.insert(*slot, ctip);
            }
        }

        let mut new_ctips = BTreeMap::new();
        for (vout, output) in transaction.output.iter().enumerate() {
            let Some(slot) = treasury_slot(&output.script_pubkey) else {
                continue;
            };
            if !state.active_slots.contains_key(&slot) {
                continue;
            }
            if new_ctips
                .insert(
                    slot,
                    NewCtipV2 {
                        vout,
                        value_sat: output.value.to_sat(),
                    },
                )
                .is_some()
            {
                return Err(Bip300ReplayErrorV2::MultipleTreasuryOutputs);
            }
        }

        if spent_ctips.keys().any(|slot| !new_ctips.contains_key(slot)) {
            return Err(Bip300ReplayErrorV2::TreasurySpentWithoutReplacement);
        }
        if new_ctips.is_empty() {
            continue;
        }

        let mut increases = Vec::new();
        let mut decreases = Vec::new();
        for (slot, new_ctip) in &new_ctips {
            let active = state.active_slots.get(slot).expect("active CTIP slot");
            let old_value = match active.ctip {
                Some(old_ctip) => {
                    if !spent_ctips.contains_key(slot) {
                        return Err(Bip300ReplayErrorV2::OldCtipUnspent);
                    }
                    old_ctip.value_sat
                }
                None => 0,
            };
            if new_ctip.value_sat == old_value {
                return Err(Bip300ReplayErrorV2::ZeroCtipDelta);
            }
            if new_ctip.value_sat > old_value {
                increases.push((*slot, *new_ctip, old_value));
            } else {
                decreases.push((*slot, *new_ctip));
            }
        }
        if decreases.len() > 1 || (!decreases.is_empty() && !increases.is_empty()) {
            return Err(Bip300ReplayErrorV2::AmbiguousM5M6);
        }

        if let Some((slot, new_ctip)) = decreases.first().copied() {
            if transaction.input.len() != 1 {
                return Err(Bip300ReplayErrorV2::M6InputCount);
            }
            if new_ctip.vout != 0 {
                return Err(Bip300ReplayErrorV2::M6TreasuryOutputIndex);
            }
            let old_ctip = spent_ctips
                .get(&slot)
                .copied()
                .ok_or(Bip300ReplayErrorV2::MalformedState)?;
            successful_m6s.push(approve_m6(
                state,
                slot,
                transaction,
                old_ctip,
                new_ctip.value_sat,
                block_hash,
                height,
            )?);
            continue;
        }

        let mut validated = Vec::new();
        for (slot, new_ctip, old_value) in increases {
            let address = transaction
                .output
                .get(new_ctip.vout + 1)
                .and_then(|output| single_op_return_push(&output.script_pubkey))
                .ok_or(Bip300ReplayErrorV2::MissingDepositAddress)?;
            validated.push((
                slot,
                new_ctip,
                new_ctip
                    .value_sat
                    .checked_sub(old_value)
                    .ok_or(Bip300ReplayErrorV2::AmountOverflow)?,
                address.to_vec(),
            ));
        }
        for (slot, new_ctip, value_sat, address) in validated {
            let active = state.active_slots.get_mut(&slot).expect("active M5 slot");
            let prior_ctip = active.ctip;
            let sequence = active.next_treasury_sequence;
            active.next_treasury_sequence = active
                .next_treasury_sequence
                .checked_add(1)
                .ok_or(Bip300ReplayErrorV2::AmountOverflow)?;
            let ctip = Bip300CtipV2 {
                outpoint: OutPoint {
                    txid: transaction.compute_txid(),
                    vout: u32::try_from(new_ctip.vout)
                        .map_err(|_| Bip300ReplayErrorV2::OutputIndexOverflow)?,
                },
                value_sat: new_ctip.value_sat,
                sequence,
            };
            active.ctip = Some(ctip);
            deposits.push(Bip300DepositV2 {
                slot,
                prior_ctip,
                outpoint: ctip,
                block_hash,
                block_height: height,
                value_sat,
                address,
            });
        }
    }
    Ok((deposits, successful_m6s, matching_m8_requests))
}

/// Apply a structurally/PoW/script-verified Bitcoin block to all 256 slots.
/// The caller composes this with the full block verifier; this relation owns
/// every BIP300/301 state transition and commits only on complete success.
pub fn apply_bip300_block_v2(
    state: &Bip300AllSlotStateV2,
    block: &Block,
) -> Result<(Bip300AllSlotStateV2, Bip300BlockEffectsV2), Bip300ReplayErrorV2> {
    apply_bip300_block_with_policy(state, block, ReplayPolicy::UniformV2)
}

fn apply_bip300_block_with_policy(
    state: &Bip300AllSlotStateV2,
    block: &Block,
    policy: ReplayPolicy,
) -> Result<(Bip300AllSlotStateV2, Bip300BlockEffectsV2), Bip300ReplayErrorV2> {
    state.validate_with_policy(policy)?;
    let block_hash = block.block_hash();
    if state.next_height == 0 {
        if block_hash != state.network_genesis {
            return Err(Bip300ReplayErrorV2::WrongGenesis);
        }
        if block.header.prev_blockhash != BlockHash::all_zeros() {
            return Err(Bip300ReplayErrorV2::BrokenParentLink);
        }
    } else if state.tip_hash != Some(block.header.prev_blockhash) {
        return Err(Bip300ReplayErrorV2::BrokenParentLink);
    }
    let coinbase = block
        .txdata
        .first()
        .ok_or(Bip300ReplayErrorV2::BrokenParentLink)?;
    let scripts = coinbase
        .output
        .iter()
        .map(|output| output.script_pubkey.clone())
        .collect::<Vec<_>>();
    let (mut next, coinbase_effects) =
        apply_bip300_coinbase_with_policy(state, state.next_height, &scripts, policy)?;
    let bmm = coinbase_effects
        .bmm_commitments
        .iter()
        .map(|entry| (entry.slot, entry.child_hash))
        .collect::<BTreeMap<_, _>>();
    let (deposits, successful_m6s, matching_m8_requests) = if policy.enabled(state.next_height) {
        apply_transactions(
            &mut next,
            &block.txdata,
            state.next_height,
            block_hash,
            block.header.prev_blockhash,
            &bmm,
            policy,
        )?
    } else {
        (Vec::new(), Vec::new(), 0)
    };
    next.tip_hash = Some(block_hash);
    next.next_height = next
        .next_height
        .checked_add(1)
        .ok_or(Bip300ReplayErrorV2::AmountOverflow)?;
    next.validate_with_policy(policy)?;
    Ok((
        next,
        Bip300BlockEffectsV2 {
            activations: coinbase_effects.activations,
            deposits,
            successful_m6s,
            effective_m4: coinbase_effects.effective_m4,
            expired_m6ids: coinbase_effects.expired_m6ids,
            bmm_commitments: coinbase_effects.bmm_commitments,
            matching_m8_requests,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute;
    use bitcoin::block::{Header, Version as BlockVersion};
    use bitcoin::pow::CompactTarget;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, Sequence, TxIn, TxMerkleNode, TxOut, Witness};

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

    fn m2(slot: u8, proposal_hash: [u8; 32]) -> ScriptBuf {
        let mut payload = M2_TAG.to_vec();
        payload.push(slot);
        payload.extend_from_slice(&proposal_hash);
        op_return(&payload)
    }

    fn initialized() -> Bip300AllSlotStateV2 {
        let mut state = Bip300AllSlotStateV2::before_genesis(
            BlockHash::from_byte_array([1; 32]),
            BIP300_REVIEWED_SHORT_NETWORK_PARAMETERS_V2,
        )
        .unwrap();
        // Coinbase message execution is composed inside the full block
        // transition. Tests start immediately after a verified genesis.
        state.next_height = 1;
        state.tip_hash = Some(state.network_genesis);
        state
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

    fn treasury(slot: u8) -> ScriptBuf {
        ScriptBuf::from_bytes(vec![OP_DRIVECHAIN, 1, slot, 0x51])
    }

    fn synthetic_block(previous: BlockHash, txdata: Vec<Transaction>) -> Block {
        Block {
            header: Header {
                version: BlockVersion::ONE,
                prev_blockhash: previous,
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1,
                bits: CompactTarget::from_consensus(0x207fffff),
                nonce: 0,
            },
            txdata,
        }
    }

    fn alpha_withdrawal_test_parameters() -> Bip300ConsensusParametersV2 {
        // These are only the withdrawal values reported by the current live
        // Alpha deployment. The proposal values are independent valid test
        // inputs; this fixture is not a claim about the complete Alpha policy.
        Bip300ConsensusParametersV2 {
            proposal_max_age: 10,
            proposal_activation_threshold: 5,
            withdrawal_max_age: 144,
            withdrawal_inclusion_threshold: 72,
        }
    }

    #[test]
    fn proposal_activation_is_slot_generic_ordered_and_atomic() {
        let mut state = initialized();
        let description = b"network-agnostic-sidechain";
        let proposal_hash = sha256d::Hash::hash(description).to_byte_array();
        let (next, _) = apply_bip300_coinbase_messages_v2(
            &state,
            1,
            &[m1(0, description), m1(255, description)],
        )
        .unwrap();
        state = next;
        state.next_height += 1;
        for height in 2..=7 {
            let (next, effects) = apply_bip300_coinbase_messages_v2(
                &state,
                height,
                &[m2(0, proposal_hash), m2(255, proposal_hash)],
            )
            .unwrap();
            state = next;
            state.next_height += 1;
            if height < 7 {
                assert!(effects.activations.is_empty());
            } else {
                assert_eq!(effects.activations.len(), 2);
            }
        }
        assert_eq!(
            state.active_slots.keys().copied().collect::<Vec<_>>(),
            [0, 255]
        );

        let before = state.clone();
        assert_eq!(
            apply_bip300_coinbase_messages_v2(
                &state,
                state.next_height,
                &[m2(0, proposal_hash), m2(0, proposal_hash)],
            ),
            Err(Bip300ReplayErrorV2::DuplicateM2)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn network_genesis_and_state_shape_fail_closed() {
        assert_eq!(
            Bip300AllSlotStateV2::before_genesis(
                BlockHash::all_zeros(),
                BIP300_REVIEWED_SHORT_NETWORK_PARAMETERS_V2,
            ),
            Err(Bip300ReplayErrorV2::ZeroGenesis)
        );
        let mut state = initialized();
        let commitment = state.commitment().unwrap();
        let mut other_network = state.clone();
        other_network.network_genesis = BlockHash::from_byte_array([2; 32]);
        assert_ne!(other_network.commitment().unwrap(), commitment);
        let mut other_parameters = state.clone();
        other_parameters
            .consensus_parameters
            .withdrawal_inclusion_threshold = 6;
        assert_ne!(other_parameters.commitment().unwrap(), commitment);
        let mut invalid_parameters = state.clone();
        invalid_parameters
            .consensus_parameters
            .proposal_activation_threshold = 11;
        assert_eq!(
            invalid_parameters.validate(),
            Err(Bip300ReplayErrorV2::InvalidConsensusParameters)
        );
        state
            .previous_effective_m4
            .insert(1, Bip300EffectiveM4ActionV2::Alarm);
        assert_eq!(state.validate(), Err(Bip300ReplayErrorV2::MalformedState));
    }

    #[test]
    fn m5_m6_and_m8_are_exact_atomic_and_slot_generic() {
        let mut state = initialized();
        state.active_slots.insert(
            255,
            Bip300ActiveSlotV2 {
                proposal_hash: [3; 32],
                activation_height: 0,
                ctip: None,
                next_treasury_sequence: 0,
                pending_m6ids: Vec::new(),
            },
        );
        let m5 = transaction(
            OutPoint::null(),
            vec![
                TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: treasury(255),
                },
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: op_return(b"deposit-address"),
                },
            ],
        );
        let placeholder = transaction(OutPoint::null(), Vec::new());
        let block_hash = BlockHash::from_byte_array([4; 32]);
        let previous = state.tip_hash.unwrap();
        let (deposits, m6s, _) = apply_transactions(
            &mut state,
            &[placeholder.clone(), m5.clone()],
            1,
            block_hash,
            previous,
            &BTreeMap::new(),
            ReplayPolicy::UniformV2,
        )
        .unwrap();
        assert_eq!(deposits.len(), 1);
        assert_eq!(deposits[0].slot, 255);
        assert_eq!(deposits[0].value_sat, 1_000);
        assert_eq!(deposits[0].address, b"deposit-address");
        assert_eq!(deposits[0].prior_ctip, None);
        assert!(m6s.is_empty());

        let old_ctip = state.active_slots[&255].ctip.unwrap();
        // Two later deposits in one block must each expose the immediately
        // preceding treasury, rather than both reusing the block-start CTIP.
        let mut chained_state = state.clone();
        let deposit_a = transaction(old_ctip.outpoint, vec![
            TxOut { value: Amount::from_sat(1_100), script_pubkey: treasury(255) },
            TxOut { value: Amount::ZERO, script_pubkey: op_return(b"address-a") },
        ]);
        let deposit_b = transaction(OutPoint { txid: deposit_a.compute_txid(), vout: 0 }, vec![
            TxOut { value: Amount::from_sat(1_300), script_pubkey: treasury(255) },
            TxOut { value: Amount::ZERO, script_pubkey: op_return(b"address-b") },
        ]);
        let (chained, _, _) = apply_transactions(
            &mut chained_state, &[placeholder.clone(), deposit_a, deposit_b],
            2, block_hash, previous, &BTreeMap::new(), ReplayPolicy::UniformV2,
        ).unwrap();
        assert_eq!(chained.len(), 2);
        assert_eq!(chained[0].prior_ctip, Some(old_ctip));
        assert_eq!(chained[1].prior_ctip, Some(chained[0].outpoint));
        assert_eq!(chained[0].value_sat, 100);
        assert_eq!(chained[1].value_sat, 200);
        let m6 = transaction(
            old_ctip.outpoint,
            vec![
                TxOut {
                    value: Amount::from_sat(900),
                    script_pubkey: treasury(255),
                },
                TxOut {
                    value: Amount::from_sat(50),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                },
            ],
        );
        let m6id = generic_m6id(&m6, 1_000, 900).unwrap();
        state.active_slots.get_mut(&255).unwrap().pending_m6ids = vec![Bip300PendingM6idV2 {
            m6id,
            proposal_height: 1,
            score: state.consensus_parameters.withdrawal_inclusion_threshold + 1,
        }];
        let (_, approvals, _) = apply_transactions(
            &mut state,
            &[placeholder.clone(), m6.clone()],
            1,
            block_hash,
            previous,
            &BTreeMap::new(),
            ReplayPolicy::UniformV2,
        )
        .unwrap();
        assert_eq!(approvals.len(), 1);
        assert_eq!(approvals[0].m6id, m6id);
        assert_eq!(state.active_slots[&255].ctip.unwrap().value_sat, 900);

        let child = BlockHash::from_byte_array([5; 32]);
        let mut m8_payload = M8_TAG.to_vec();
        m8_payload.push(255);
        m8_payload.extend_from_slice(child.as_byte_array());
        m8_payload.extend_from_slice(previous.as_byte_array());
        let m8 = transaction(
            OutPoint::null(),
            vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: op_return(&m8_payload),
            }],
        );
        let mut bmm = BTreeMap::new();
        bmm.insert(255, child);
        assert_eq!(
            apply_transactions(
                &mut state,
                &[placeholder.clone(), m8.clone()],
                1,
                block_hash,
                previous,
                &bmm,
                ReplayPolicy::UniformV2,
            )
            .unwrap()
            .2,
            1
        );
        let before = state.clone();
        bmm.insert(255, BlockHash::from_byte_array([6; 32]));
        assert_eq!(
            apply_transactions(
                &mut state,
                &[placeholder, m8],
                1,
                block_hash,
                previous,
                &bmm,
                ReplayPolicy::UniformV2,
            ),
            Err(Bip300ReplayErrorV2::M8WrongChildHash)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn configured_alpha_withdrawal_age_is_inclusive_at_144_and_expires_at_145() {
        let slot = 24;
        let m6id = Txid::from_byte_array([0x61; 32]);
        let parent = BlockHash::from_byte_array([0x62; 32]);
        let mut state = Bip300AllSlotStateV2 {
            network_genesis: BlockHash::from_byte_array([0x63; 32]),
            consensus_parameters: alpha_withdrawal_test_parameters(),
            next_height: 144,
            tip_hash: Some(parent),
            proposals: BTreeMap::new(),
            active_slots: BTreeMap::from([(
                slot,
                Bip300ActiveSlotV2 {
                    proposal_hash: [0x64; 32],
                    activation_height: 0,
                    ctip: None,
                    next_treasury_sequence: 0,
                    pending_m6ids: vec![Bip300PendingM6idV2 {
                        m6id,
                        proposal_height: 0,
                        score: 73,
                    }],
                },
            )]),
            previous_effective_m4: BTreeMap::new(),
        };
        state.validate().unwrap();

        let coinbase = transaction(OutPoint::null(), Vec::new());
        let height_144 = synthetic_block(parent, vec![coinbase.clone()]);
        let (next, effects) = apply_bip300_block_v2(&state, &height_144).unwrap();
        assert!(effects.expired_m6ids.is_empty());
        assert_eq!(next.active_slots[&slot].pending_m6ids[0].m6id, m6id);

        state = next;
        let height_145 = synthetic_block(state.tip_hash.unwrap(), vec![coinbase]);
        let (next, effects) = apply_bip300_block_v2(&state, &height_145).unwrap();
        assert_eq!(effects.expired_m6ids, vec![(slot, m6id)]);
        assert!(next.active_slots[&slot].pending_m6ids.is_empty());
    }

    #[test]
    fn configured_alpha_withdrawal_requires_score_strictly_greater_than_72() {
        let slot = 24;
        let old_ctip = Bip300CtipV2 {
            outpoint: OutPoint {
                txid: Txid::from_byte_array([0x71; 32]),
                vout: 0,
            },
            value_sat: 1_000,
            sequence: 0,
        };
        let withdrawal = transaction(
            old_ctip.outpoint,
            vec![
                TxOut {
                    value: Amount::from_sat(900),
                    script_pubkey: treasury(slot),
                },
                TxOut {
                    value: Amount::from_sat(50),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                },
            ],
        );
        let m6id = generic_m6id(&withdrawal, old_ctip.value_sat, 900).unwrap();
        let parent = BlockHash::from_byte_array([0x72; 32]);
        let state_with_score_at_height = |score, next_height| Bip300AllSlotStateV2 {
            network_genesis: BlockHash::from_byte_array([0x73; 32]),
            consensus_parameters: alpha_withdrawal_test_parameters(),
            next_height,
            tip_hash: Some(parent),
            proposals: BTreeMap::new(),
            active_slots: BTreeMap::from([(
                slot,
                Bip300ActiveSlotV2 {
                    proposal_hash: [0x74; 32],
                    activation_height: 0,
                    ctip: Some(old_ctip),
                    next_treasury_sequence: 1,
                    pending_m6ids: vec![Bip300PendingM6idV2 {
                        m6id,
                        proposal_height: 0,
                        score,
                    }],
                },
            )]),
            previous_effective_m4: BTreeMap::new(),
        };
        let coinbase = transaction(OutPoint::null(), Vec::new());
        let block = synthetic_block(parent, vec![coinbase, withdrawal]);

        let score_72 = state_with_score_at_height(72, 144);
        score_72.validate().unwrap();
        assert_eq!(
            apply_bip300_block_v2(&score_72, &block),
            Err(Bip300ReplayErrorV2::M6InsufficientScore)
        );

        let score_73 = state_with_score_at_height(73, 144);
        score_73.validate().unwrap();
        let (next, effects) = apply_bip300_block_v2(&score_73, &block).unwrap();
        assert_eq!(effects.successful_m6s.len(), 1);
        assert_eq!(effects.successful_m6s[0].m6id, m6id);
        assert_eq!(next.active_slots[&slot].ctip.unwrap().value_sat, 900);
        assert!(next.active_slots[&slot].pending_m6ids.is_empty());

        let expired_score_73 = state_with_score_at_height(73, 145);
        expired_score_73.validate().unwrap();
        assert_eq!(
            apply_bip300_block_v2(&expired_score_73, &block),
            Err(Bip300ReplayErrorV2::M6MissingPendingBundle)
        );
    }

    #[test]
    fn block_wrapper_binds_configured_genesis_parent_and_commits_atomically() {
        let coinbase = transaction(OutPoint::null(), Vec::new());
        let genesis = synthetic_block(BlockHash::all_zeros(), vec![coinbase.clone()]);
        let mut state = Bip300AllSlotStateV2::before_genesis(
            genesis.block_hash(),
            BIP300_REVIEWED_SHORT_NETWORK_PARAMETERS_V2,
        )
        .unwrap();
        let (next, effects) = apply_bip300_block_v2(&state, &genesis).unwrap();
        assert!(effects.activations.is_empty());
        assert_eq!(next.next_height, 1);
        assert_eq!(next.tip_hash, Some(genesis.block_hash()));

        let child = synthetic_block(genesis.block_hash(), vec![coinbase]);
        state = next;
        let (next, _) = apply_bip300_block_v2(&state, &child).unwrap();
        assert_eq!(next.next_height, 2);

        let wrong_parent = synthetic_block(BlockHash::from_byte_array([9; 32]), Vec::new());
        let before = next.clone();
        assert_eq!(
            apply_bip300_block_v2(&next, &wrong_parent),
            Err(Bip300ReplayErrorV2::BrokenParentLink)
        );
        assert_eq!(next, before);

        let wrong_genesis_state = Bip300AllSlotStateV2::before_genesis(
            BlockHash::from_byte_array([8; 32]),
            BIP300_REVIEWED_SHORT_NETWORK_PARAMETERS_V2,
        )
        .unwrap();
        assert_eq!(
            apply_bip300_block_v2(&wrong_genesis_state, &genesis),
            Err(Bip300ReplayErrorV2::WrongGenesis)
        );
    }
}
