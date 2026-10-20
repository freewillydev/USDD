//! Ordered, header-authenticated forced actions for matcher censorship recovery.
//!
//! The Elements inclusion proof is verified by the chain adapter. This module
//! verifies the consensus-shaped action, append-only accumulator, cursor, and
//! parent-height deadline semantics consumed by the private transition proof.

use crate::codec::{put_u16, put_u32, put_u64, put_u8, CanonicalEncode, Decoder};
use crate::hash::{canonical_hash, tagged_hash, Hash32};
use crate::order::{OrderFlags, SignedCancelOrder, SignedLimitOrder, TimeInForce};
use crate::queue::SignedWithdrawalRequest;
use crate::ProtocolError;

pub const FORCED_ACTION_PAYLOAD_MAGIC: [u8; 4] = *b"ECXF";
pub const FORCED_ACTION_PAYLOAD_VERSION: u8 = 1;
/// Existing V1 transition limits. These bound the forced and deposit inboxes
/// together and are exported so recursive successors cannot silently narrow
/// or widen the accepted V1 state space.
pub const MAX_COMBINED_UNCONSUMED_INBOX_ENTRIES_V1: u64 = 64;
pub const MAX_COMBINED_SAME_DEADLINE_APPENDS_V1: usize = 64;
pub const MAX_COMBINED_PENDING_INBOX_WITNESS_ENTRIES_V1: usize = 448;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ForcedActionV1 {
    Cancel(SignedCancelOrder),
    ReduceOnlyIoc(SignedLimitOrder),
    Withdraw(SignedWithdrawalRequest),
}

impl ForcedActionV1 {
    pub fn chain_id(&self) -> Hash32 {
        match self {
            Self::Cancel(value) => value.cancel.chain_id,
            Self::ReduceOnlyIoc(value) => value.order.chain_id,
            Self::Withdraw(value) => value.request.chain_id,
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Cancel(value) => value.verify(),
            Self::ReduceOnlyIoc(value) => {
                value.verify()?;
                if value.order.time_in_force != TimeInForce::ImmediateOrCancel
                    || !value.order.flags.contains(OrderFlags::REDUCE_ONLY)
                    || value.order.flags.contains(OrderFlags::POST_ONLY)
                {
                    return Err(ProtocolError::InvalidForcedAction);
                }
                Ok(())
            }
            Self::Withdraw(value) => value.verify(),
        }
    }

    pub fn action_hash(&self) -> Hash32 {
        canonical_hash("ECX/forced-action/v1", self)
    }

    /// Canonical bytes placed in one exact OP_RETURN push. Consensus extracts
    /// these bytes, decodes them with this routine, and appends the resulting
    /// locator/action to the forced inbox. Bodies are intentionally on-chain so
    /// a censored matcher cannot withhold the data needed by another prover.
    pub fn payload_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let body = match self {
            Self::Cancel(value) => value.canonical_bytes(),
            Self::ReduceOnlyIoc(value) => value.canonical_bytes(),
            Self::Withdraw(value) => value.canonical_bytes(),
        };
        let body_len = u16::try_from(body.len()).map_err(|_| ProtocolError::InvalidForcedAction)?;
        let mut payload = Vec::with_capacity(8 + body.len());
        payload.extend_from_slice(&FORCED_ACTION_PAYLOAD_MAGIC);
        put_u8(&mut payload, FORCED_ACTION_PAYLOAD_VERSION);
        put_u8(
            &mut payload,
            match self {
                Self::Cancel(_) => 0,
                Self::ReduceOnlyIoc(_) => 1,
                Self::Withdraw(_) => 2,
            },
        );
        put_u16(&mut payload, body_len);
        payload.extend_from_slice(&body);
        Ok(payload)
    }

    pub fn decode_payload(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() < 8 {
            return Err(ProtocolError::InvalidForcedAction);
        }
        let mut decoder = Decoder::new(payload);
        if decoder.take::<4>()? != FORCED_ACTION_PAYLOAD_MAGIC
            || decoder.u8()? != FORCED_ACTION_PAYLOAD_VERSION
        {
            return Err(ProtocolError::InvalidForcedAction);
        }
        let kind = decoder.u8()?;
        let length = usize::from(decoder.u16()?);
        let body = payload.get(8..).ok_or(ProtocolError::UnexpectedEnd)?;
        if body.len() != length {
            return Err(ProtocolError::InvalidForcedAction);
        }
        // The header was consumed independently; reject any non-canonical body
        // length by the fixed-width action decoders below.
        let action = match kind {
            0 => Self::Cancel(SignedCancelOrder::decode_fixed(body)?),
            1 => Self::ReduceOnlyIoc(SignedLimitOrder::decode_fixed(body)?),
            2 => Self::Withdraw(SignedWithdrawalRequest::decode_fixed(body)?),
            other => return Err(ProtocolError::InvalidDiscriminant(other)),
        };
        action.validate()?;
        Ok(action)
    }
}

impl CanonicalEncode for ForcedActionV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        match self {
            Self::Cancel(value) => {
                put_u8(out, 0);
                value.encode_to(out);
            }
            Self::ReduceOnlyIoc(value) => {
                put_u8(out, 1);
                value.encode_to(out);
            }
            Self::Withdraw(value) => {
                put_u8(out, 2);
                value.encode_to(out);
            }
        }
    }
}

/// A canonical action extracted from an Elements transaction and authenticated
/// by the source adapter against the BMM-approved child-header chain.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ForcedActionEntryV1 {
    pub version: u8,
    pub chain_id: Hash32,
    pub index: u64,
    pub previous_root: Hash32,
    pub enqueued_sidechain_height: u64,
    pub enqueued_parent_height: u64,
    pub source_txid: Hash32,
    pub source_vout: u32,
    pub action: ForcedActionV1,
}

impl ForcedActionEntryV1 {
    pub const VERSION: u8 = 1;

    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.action.validate()?;
        if self.version != Self::VERSION
            || self.chain_id == [0; 32]
            || self.chain_id != self.action.chain_id()
            || self.previous_root == [0; 32]
            || self.enqueued_sidechain_height == 0
            || self.enqueued_parent_height == 0
            || self.source_txid == [0; 32]
        {
            return Err(ProtocolError::InvalidForcedAction);
        }
        Ok(())
    }

    pub fn entry_hash(&self) -> Hash32 {
        canonical_hash("ECX/forced-action-entry/v1", self)
    }

    pub fn next_root(&self) -> Hash32 {
        let mut bytes = Vec::with_capacity(72);
        bytes.extend_from_slice(&self.previous_root);
        put_u64(&mut bytes, self.index);
        bytes.extend_from_slice(&self.entry_hash());
        tagged_hash("ECX/forced-inbox-step/v1", &bytes)
    }

    pub fn deadline(&self, forced_inclusion_blocks: u32) -> Result<u64, ProtocolError> {
        if forced_inclusion_blocks == 0 {
            return Err(ProtocolError::InvalidCentralMatcherConfiguration);
        }
        self.enqueued_parent_height
            .checked_add(u64::from(forced_inclusion_blocks))
            .ok_or(ProtocolError::ArithmeticOverflow)
    }

    pub fn is_overdue(
        &self,
        current_parent_height: u64,
        forced_inclusion_blocks: u32,
    ) -> Result<bool, ProtocolError> {
        Ok(current_parent_height >= self.deadline(forced_inclusion_blocks)?)
    }
}

impl CanonicalEncode for ForcedActionEntryV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.chain_id);
        put_u64(out, self.index);
        out.extend_from_slice(&self.previous_root);
        put_u64(out, self.enqueued_sidechain_height);
        put_u64(out, self.enqueued_parent_height);
        out.extend_from_slice(&self.source_txid);
        put_u32(out, self.source_vout);
        self.action.encode_to(out);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ForcedInboxStateV1 {
    /// Root after every action observed through `entry_count`.
    pub head_root: Hash32,
    pub entry_count: u64,
    /// Root immediately after the last consumed action.
    pub processed_root: Hash32,
    pub cursor: u64,
}

impl ForcedInboxStateV1 {
    pub fn genesis(forced_action_domain: Hash32, chain_id: Hash32) -> Result<Self, ProtocolError> {
        if forced_action_domain == [0; 32] || chain_id == [0; 32] {
            return Err(ProtocolError::InvalidForcedAction);
        }
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&forced_action_domain);
        bytes[32..].copy_from_slice(&chain_id);
        let root = tagged_hash("ECX/forced-inbox-genesis/v1", &bytes);
        Ok(Self {
            head_root: root,
            entry_count: 0,
            processed_root: root,
            cursor: 0,
        })
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.head_root == [0; 32]
            || self.processed_root == [0; 32]
            || self.cursor > self.entry_count
            || (self.cursor == self.entry_count && self.processed_root != self.head_root)
        {
            return Err(ProtocolError::InvalidForcedInbox);
        }
        Ok(())
    }
}

impl CanonicalEncode for ForcedInboxStateV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.head_root);
        put_u64(out, self.entry_count);
        out.extend_from_slice(&self.processed_root);
        put_u64(out, self.cursor);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ForcedInboxTransitionV1 {
    /// Every unconsumed entry from `previous.cursor` through `next.entry_count`.
    pub pending_entries: Vec<ForcedActionEntryV1>,
    /// Number of entries consumed from the front of `pending_entries`.
    pub consumed_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForcedInboxOutcome {
    pub had_overdue_action: bool,
    pub first_unconsumed_overdue: bool,
}

impl ForcedInboxTransitionV1 {
    pub fn verify(
        &self,
        chain_id: Hash32,
        previous: ForcedInboxStateV1,
        next: ForcedInboxStateV1,
        current_parent_height: u64,
        forced_inclusion_blocks: u32,
    ) -> Result<ForcedInboxOutcome, ProtocolError> {
        previous.validate()?;
        next.validate()?;
        if chain_id == [0; 32]
            || next.entry_count < previous.entry_count
            || next.cursor < previous.cursor
            || usize::try_from(self.consumed_count)
                .map_err(|_| ProtocolError::ArithmeticOverflow)?
                > self.pending_entries.len()
        {
            return Err(ProtocolError::InvalidForcedInbox);
        }

        let mut root = previous.processed_root;
        let mut index = previous.cursor;
        let mut root_after_consumed = root;
        let consumed_end = previous
            .cursor
            .checked_add(u64::from(self.consumed_count))
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        let mut observed_previous_head = previous.cursor == previous.entry_count;
        let mut last_sidechain_height = 0u64;
        let mut last_parent_height = 0u64;
        let mut had_overdue_action = false;

        for entry in &self.pending_entries {
            entry.validate()?;
            if entry.chain_id != chain_id
                || entry.index != index
                || entry.previous_root != root
                || (last_sidechain_height != 0
                    && entry.enqueued_sidechain_height < last_sidechain_height)
                || (last_parent_height != 0 && entry.enqueued_parent_height < last_parent_height)
            {
                return Err(ProtocolError::InvalidForcedInbox);
            }
            had_overdue_action |=
                entry.is_overdue(current_parent_height, forced_inclusion_blocks)?;
            root = entry.next_root();
            index = index
                .checked_add(1)
                .ok_or(ProtocolError::ArithmeticOverflow)?;
            last_sidechain_height = entry.enqueued_sidechain_height;
            last_parent_height = entry.enqueued_parent_height;
            if index == consumed_end {
                root_after_consumed = root;
            }
            if index == previous.entry_count {
                if root != previous.head_root {
                    return Err(ProtocolError::InvalidForcedInbox);
                }
                observed_previous_head = true;
            }
        }

        if !observed_previous_head
            || index != next.entry_count
            || root != next.head_root
            || next.cursor != consumed_end
            || next.processed_root != root_after_consumed
        {
            return Err(ProtocolError::InvalidForcedInbox);
        }
        let consumed =
            usize::try_from(self.consumed_count).map_err(|_| ProtocolError::ArithmeticOverflow)?;
        let first_unconsumed_overdue = self.pending_entries.get(consumed).is_some_and(|entry| {
            entry
                .is_overdue(current_parent_height, forced_inclusion_blocks)
                .unwrap_or(true)
        });
        if first_unconsumed_overdue {
            return Err(ProtocolError::ForcedActionDeadline);
        }
        Ok(ForcedInboxOutcome {
            had_overdue_action,
            first_unconsumed_overdue,
        })
    }

    pub fn consumed(&self) -> Result<&[ForcedActionEntryV1], ProtocolError> {
        let count =
            usize::try_from(self.consumed_count).map_err(|_| ProtocolError::ArithmeticOverflow)?;
        self.pending_entries
            .get(..count)
            .ok_or(ProtocolError::InvalidForcedInbox)
    }
}

#[cfg(test)]
mod tests {
    use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

    use super::*;
    use crate::order::{CancelOrder, SignedCancelOrder};
    use crate::types::{XOnlyKey, ECX_USDD_MARKET};

    fn cancel(secret: &SecretKey, chain_id: Hash32, nonce: u64) -> SignedCancelOrder {
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), secret);
        let (public, _) = XOnlyPublicKey::from_keypair(&keypair);
        SignedCancelOrder::sign(
            CancelOrder {
                version: CancelOrder::VERSION,
                chain_id,
                market: ECX_USDD_MARKET,
                trader: XOnlyKey(public.serialize()),
                order_id: [9; 32],
                nonce,
                valid_from_height: 1,
                expires_at_height: 100,
            },
            secret,
        )
        .unwrap()
    }

    fn entry(
        secret: &SecretKey,
        chain_id: Hash32,
        index: u64,
        previous_root: Hash32,
        parent_height: u64,
    ) -> ForcedActionEntryV1 {
        ForcedActionEntryV1 {
            version: ForcedActionEntryV1::VERSION,
            chain_id,
            index,
            previous_root,
            enqueued_sidechain_height: 10 + index,
            enqueued_parent_height: parent_height,
            source_txid: [5 + index as u8; 32],
            source_vout: 0,
            action: ForcedActionV1::Cancel(cancel(secret, chain_id, index + 1)),
        }
    }

    #[test]
    fn append_and_consume_are_one_ordered_chain() {
        let chain_id = [1; 32];
        let previous = ForcedInboxStateV1::genesis([2; 32], chain_id).unwrap();
        let secret = SecretKey::from_slice(&[4; 32]).unwrap();
        let first = entry(&secret, chain_id, 0, previous.head_root, 100);
        let second = entry(&secret, chain_id, 1, first.next_root(), 101);
        let next = ForcedInboxStateV1 {
            head_root: second.next_root(),
            entry_count: 2,
            processed_root: first.next_root(),
            cursor: 1,
        };
        let witness = ForcedInboxTransitionV1 {
            pending_entries: vec![first, second],
            consumed_count: 1,
        };
        let outcome = witness.verify(chain_id, previous, next, 104, 6).unwrap();
        assert!(!outcome.had_overdue_action);
        assert_eq!(witness.consumed().unwrap().len(), 1);
    }

    #[test]
    fn overdue_head_must_be_consumed() {
        let chain_id = [1; 32];
        let previous = ForcedInboxStateV1::genesis([2; 32], chain_id).unwrap();
        let secret = SecretKey::from_slice(&[4; 32]).unwrap();
        let first = entry(&secret, chain_id, 0, previous.head_root, 100);
        let next = ForcedInboxStateV1 {
            head_root: first.next_root(),
            entry_count: 1,
            processed_root: previous.processed_root,
            cursor: 0,
        };
        let witness = ForcedInboxTransitionV1 {
            pending_entries: vec![first],
            consumed_count: 0,
        };
        assert_eq!(
            witness.verify(chain_id, previous, next, 106, 6),
            Err(ProtocolError::ForcedActionDeadline)
        );
    }

    #[test]
    fn reordered_or_non_reduce_only_action_fails() {
        let chain_id = [1; 32];
        let previous = ForcedInboxStateV1::genesis([2; 32], chain_id).unwrap();
        let secret = SecretKey::from_slice(&[4; 32]).unwrap();
        let mut first = entry(&secret, chain_id, 1, previous.head_root, 100);
        assert_eq!(first.validate(), Ok(()));
        let next = ForcedInboxStateV1 {
            head_root: first.next_root(),
            entry_count: 1,
            processed_root: first.next_root(),
            cursor: 1,
        };
        let witness = ForcedInboxTransitionV1 {
            pending_entries: vec![first.clone()],
            consumed_count: 1,
        };
        assert_eq!(
            witness.verify(chain_id, previous, next, 101, 6),
            Err(ProtocolError::InvalidForcedInbox)
        );
        first.action = ForcedActionV1::ReduceOnlyIoc(SignedLimitOrder {
            order: crate::order::LimitOrder {
                version: 1,
                chain_id,
                market: ECX_USDD_MARKET,
                trader: XOnlyKey([2; 32]),
                side: crate::order::Side::Buy,
                time_in_force: TimeInForce::ImmediateOrCancel,
                flags: OrderFlags::NONE,
                limit_price: crate::types::Price::new(1).unwrap(),
                quantity: crate::types::Quantity::new(1).unwrap(),
                client_order_id: [1; 16],
                max_fee_bps: 1,
                nonce: 1,
                valid_from_height: 1,
                expires_at_height: 2,
            },
            signature: crate::order::Signature64([0; 64]),
        });
        assert!(first.action.validate().is_err());
    }

    #[test]
    fn on_chain_payload_roundtrips_and_rejects_trailing_bytes() {
        let chain_id = [1; 32];
        let secret = SecretKey::from_slice(&[4; 32]).unwrap();
        let action = ForcedActionV1::Cancel(cancel(&secret, chain_id, 1));
        let payload = action.payload_bytes().unwrap();
        assert_eq!(ForcedActionV1::decode_payload(&payload).unwrap(), action);
        let mut trailing = payload;
        trailing.push(0);
        assert_eq!(
            ForcedActionV1::decode_payload(&trailing),
            Err(ProtocolError::InvalidForcedAction)
        );
    }
}
