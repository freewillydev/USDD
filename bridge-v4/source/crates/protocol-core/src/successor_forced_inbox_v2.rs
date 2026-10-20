//! Lifetime-safe forced-action inbox for the incremental successor.
//!
//! V1 payloads, accumulators, and signature domains remain unchanged. The
//! successor uses fresh version/domain bytes and direct `u128` entry/count
//! cursors so no high bits can be hidden outside the authenticated state.

use crate::codec::{put_u128, put_u16, put_u32, put_u64, put_u8, CanonicalEncode, Decoder};
use crate::configuration::MAX_TRANSITION_ACTIONS;
use crate::forced::{
    ForcedInboxOutcome, FORCED_ACTION_PAYLOAD_MAGIC, MAX_COMBINED_PENDING_INBOX_WITNESS_ENTRIES_V1,
};
use crate::hash::{canonical_hash, tagged_hash, Hash32};
use crate::merkle::ordered_root;
use crate::order::{OrderFlags, TimeInForce};
use crate::successor_action_v2::{
    SuccessorSignedCancelOrderV2, SuccessorSignedLimitOrderV2, SuccessorSignedWithdrawalRequestV2,
};
use crate::ProtocolError;

pub const SUCCESSOR_FORCED_ACTION_PAYLOAD_VERSION_V2: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SuccessorForcedActionV2 {
    Cancel(SuccessorSignedCancelOrderV2),
    ReduceOnlyIoc(SuccessorSignedLimitOrderV2),
    Withdraw(SuccessorSignedWithdrawalRequestV2),
}

impl SuccessorForcedActionV2 {
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
        canonical_hash("ECX/successor-forced-action/v2-u128", self)
    }

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
        put_u8(&mut payload, SUCCESSOR_FORCED_ACTION_PAYLOAD_VERSION_V2);
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
            || decoder.u8()? != SUCCESSOR_FORCED_ACTION_PAYLOAD_VERSION_V2
        {
            return Err(ProtocolError::InvalidForcedAction);
        }
        let kind = decoder.u8()?;
        let length = usize::from(decoder.u16()?);
        let body = payload.get(8..).ok_or(ProtocolError::UnexpectedEnd)?;
        if body.len() != length {
            return Err(ProtocolError::InvalidForcedAction);
        }
        let action = match kind {
            0 => Self::Cancel(SuccessorSignedCancelOrderV2::decode_fixed(body)?),
            1 => Self::ReduceOnlyIoc(SuccessorSignedLimitOrderV2::decode_fixed(body)?),
            2 => Self::Withdraw(SuccessorSignedWithdrawalRequestV2::decode_fixed(body)?),
            other => return Err(ProtocolError::InvalidDiscriminant(other)),
        };
        action.validate()?;
        Ok(action)
    }
}

impl CanonicalEncode for SuccessorForcedActionV2 {
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

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorForcedActionEntryV2 {
    pub version: u8,
    pub chain_id: Hash32,
    pub index: u128,
    pub previous_root: Hash32,
    pub enqueued_sidechain_height: u64,
    pub enqueued_parent_height: u64,
    pub source_txid: Hash32,
    pub source_vout: u32,
    pub action: SuccessorForcedActionV2,
}

impl SuccessorForcedActionEntryV2 {
    pub const VERSION: u8 = 2;

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
        canonical_hash("ECX/successor-forced-action-entry/v2-u128", self)
    }

    pub fn next_root(&self) -> Hash32 {
        let mut bytes = Vec::with_capacity(80);
        bytes.extend_from_slice(&self.previous_root);
        put_u128(&mut bytes, self.index);
        bytes.extend_from_slice(&self.entry_hash());
        tagged_hash("ECX/successor-forced-inbox-step/v2-u128", &bytes)
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

impl CanonicalEncode for SuccessorForcedActionEntryV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.chain_id);
        put_u128(out, self.index);
        out.extend_from_slice(&self.previous_root);
        put_u64(out, self.enqueued_sidechain_height);
        put_u64(out, self.enqueued_parent_height);
        out.extend_from_slice(&self.source_txid);
        put_u32(out, self.source_vout);
        self.action.encode_to(out);
    }
}

pub fn successor_forced_action_batch_root_v2(entries: &[SuccessorForcedActionEntryV2]) -> Hash32 {
    let ids: Vec<Hash32> = entries
        .iter()
        .map(SuccessorForcedActionEntryV2::entry_hash)
        .collect();
    ordered_root("ECX/successor-forced-action-batch/v2-u128", &ids)
}

pub fn successor_forced_inbox_state_hash_v2(state: SuccessorForcedInboxStateV2) -> Hash32 {
    canonical_hash("ECX/successor-forced-inbox-state/v2-u128", &state)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorForcedInboxStateV2 {
    pub head_root: Hash32,
    pub entry_count: u128,
    pub processed_root: Hash32,
    pub cursor: u128,
}

impl SuccessorForcedInboxStateV2 {
    pub fn genesis(forced_action_domain: Hash32, chain_id: Hash32) -> Result<Self, ProtocolError> {
        if forced_action_domain == [0; 32] || chain_id == [0; 32] {
            return Err(ProtocolError::InvalidForcedAction);
        }
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&forced_action_domain);
        bytes[32..].copy_from_slice(&chain_id);
        let root = tagged_hash("ECX/successor-forced-inbox-genesis/v2-u128", &bytes);
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

impl CanonicalEncode for SuccessorForcedInboxStateV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.head_root);
        put_u128(out, self.entry_count);
        out.extend_from_slice(&self.processed_root);
        put_u128(out, self.cursor);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorForcedInboxTransitionV2 {
    pub pending_entries: Vec<SuccessorForcedActionEntryV2>,
    pub consumed_count: u32,
}

impl SuccessorForcedInboxTransitionV2 {
    pub fn verify(
        &self,
        chain_id: Hash32,
        previous: SuccessorForcedInboxStateV2,
        next: SuccessorForcedInboxStateV2,
        current_parent_height: u64,
        forced_inclusion_blocks: u32,
    ) -> Result<ForcedInboxOutcome, ProtocolError> {
        previous.validate()?;
        next.validate()?;
        let consumed =
            usize::try_from(self.consumed_count).map_err(|_| ProtocolError::ArithmeticOverflow)?;
        if chain_id == [0; 32]
            || self.pending_entries.len() > MAX_COMBINED_PENDING_INBOX_WITNESS_ENTRIES_V1
            || next.entry_count < previous.entry_count
            || next.cursor < previous.cursor
            || consumed > self.pending_entries.len()
            || self.consumed_count > MAX_TRANSITION_ACTIONS
        {
            return Err(ProtocolError::InvalidForcedInbox);
        }

        let mut root = previous.processed_root;
        let mut index = previous.cursor;
        let mut root_after_consumed = root;
        let consumed_end = previous
            .cursor
            .checked_add(u128::from(self.consumed_count))
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
        let first_unconsumed_overdue = self.pending_entries.get(consumed).is_some_and(|entry| {
            entry
                .is_overdue(current_parent_height, forced_inclusion_blocks)
                .unwrap_or(true)
        });
        // A successor drains complete parent-height tranches.  Requiring a
        // numeric 64-entry catch-up batch was unsound once one forced IOC can
        // legitimately use all 64 immediate-root order operations by itself.
        // The recursive forced-action child separately proves that each
        // parent-height tranche fits the frozen order-operation budget.
        if first_unconsumed_overdue {
            let oldest_parent_height = self
                .pending_entries
                .first()
                .ok_or(ProtocolError::InvalidForcedInbox)?
                .enqueued_parent_height;
            let oldest_tranche_count = self
                .pending_entries
                .iter()
                .take_while(|entry| entry.enqueued_parent_height == oldest_parent_height)
                .count();
            if consumed < oldest_tranche_count {
                return Err(ProtocolError::ForcedActionDeadline);
            }
        }
        Ok(ForcedInboxOutcome {
            had_overdue_action,
            first_unconsumed_overdue,
        })
    }

    pub fn consumed(&self) -> Result<&[SuccessorForcedActionEntryV2], ProtocolError> {
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
    use crate::successor_action_v2::{SuccessorCancelOrderV2, SuccessorSignedCancelOrderV2};
    use crate::types::{XOnlyKey, ECX_USDD_MARKET};

    fn cancel(secret: &SecretKey, chain_id: Hash32, nonce: u128) -> SuccessorSignedCancelOrderV2 {
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), secret);
        let (public, _) = XOnlyPublicKey::from_keypair(&keypair);
        SuccessorSignedCancelOrderV2::sign(
            SuccessorCancelOrderV2 {
                version: SuccessorCancelOrderV2::VERSION,
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
        index: u128,
        previous_root: Hash32,
        parent_height: u64,
    ) -> SuccessorForcedActionEntryV2 {
        let mut source_txid = [5; 32];
        source_txid[16..].copy_from_slice(&(index + 1).to_be_bytes());
        SuccessorForcedActionEntryV2 {
            version: SuccessorForcedActionEntryV2::VERSION,
            chain_id,
            index,
            previous_root,
            enqueued_sidechain_height: 10,
            enqueued_parent_height: parent_height,
            source_txid,
            source_vout: 0,
            action: SuccessorForcedActionV2::Cancel(cancel(secret, chain_id, index + 1)),
        }
    }

    #[test]
    fn successor_forced_payload_and_inbox_preserve_high_u128_bits() {
        let chain_id = [1; 32];
        let domain = [2; 32];
        let secret = SecretKey::from_slice(&[4; 32]).unwrap();
        let high = (1u128 << 96) + 17;
        let action = SuccessorForcedActionV2::Cancel(cancel(&secret, chain_id, high));
        let payload = action.payload_bytes().unwrap();
        assert_eq!(
            SuccessorForcedActionV2::decode_payload(&payload).unwrap(),
            action
        );
        let mut trailing = payload;
        trailing.push(0);
        assert_eq!(
            SuccessorForcedActionV2::decode_payload(&trailing),
            Err(ProtocolError::InvalidForcedAction)
        );

        let genesis = SuccessorForcedInboxStateV2::genesis(domain, chain_id).unwrap();
        let previous = SuccessorForcedInboxStateV2 {
            head_root: [3; 32],
            entry_count: high,
            processed_root: [3; 32],
            cursor: high,
        };
        let first = entry(&secret, chain_id, high, previous.head_root, 100);
        let next = SuccessorForcedInboxStateV2 {
            head_root: first.next_root(),
            entry_count: high + 1,
            processed_root: first.next_root(),
            cursor: high + 1,
        };
        let transition = SuccessorForcedInboxTransitionV2 {
            pending_entries: vec![first],
            consumed_count: 1,
        };
        transition.verify(chain_id, previous, next, 101, 6).unwrap();
        assert_ne!(genesis.head_root, [0; 32]);
    }
}
