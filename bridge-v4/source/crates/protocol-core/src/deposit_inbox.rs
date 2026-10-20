//! Consensus-derived deposit locators and their ordered consumption cursor.
//!
//! Elements recognizes an `ECXD` marker that points at a vault output in the
//! same transaction. The node commits the exact serialized output hash and the
//! public trader key, but cannot learn the confidential asset or value. The
//! private proof supplies and verifies that opening before crediting a deposit.

use crate::codec::{put_u32, put_u64, put_u8, CanonicalEncode, Decoder};
use crate::hash::{canonical_hash, tagged_hash, Hash32};
use crate::types::XOnlyKey;
use crate::ProtocolError;
use secp256k1::XOnlyPublicKey;

pub const DEPOSIT_MARKER_MAGIC: [u8; 4] = *b"ECXD";
pub const DEPOSIT_MARKER_VERSION: u8 = 1;
pub const DEPOSIT_MARKER_LEN: usize = 4 + 1 + 32 + 4 + 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DepositMarkerV1 {
    pub chain_id: Hash32,
    pub deposit_vout: u32,
    pub trader: XOnlyKey,
}

impl DepositMarkerV1 {
    pub fn payload_bytes(self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(DEPOSIT_MARKER_LEN);
        bytes.extend_from_slice(&DEPOSIT_MARKER_MAGIC);
        put_u8(&mut bytes, DEPOSIT_MARKER_VERSION);
        bytes.extend_from_slice(&self.chain_id);
        put_u32(&mut bytes, self.deposit_vout);
        self.trader.encode_to(&mut bytes);
        Ok(bytes)
    }

    pub fn decode_payload(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != DEPOSIT_MARKER_LEN {
            return Err(ProtocolError::InvalidDepositInbox);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take::<4>()? != DEPOSIT_MARKER_MAGIC || decoder.u8()? != DEPOSIT_MARKER_VERSION {
            return Err(ProtocolError::InvalidDepositInbox);
        }
        let marker = Self {
            chain_id: decoder.take()?,
            deposit_vout: decoder.u32()?,
            trader: XOnlyKey(decoder.take()?),
        };
        decoder.finish()?;
        marker.validate()?;
        Ok(marker)
    }

    pub fn validate(self) -> Result<(), ProtocolError> {
        if self.chain_id == [0; 32]
            || XOnlyPublicKey::from_slice(&self.trader.0).is_err()
            || self.deposit_vout == u32::MAX
        {
            return Err(ProtocolError::InvalidDepositInbox);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DepositEventV1 {
    pub version: u8,
    pub chain_id: Hash32,
    pub index: u64,
    pub previous_root: Hash32,
    pub observed_sidechain_height: u64,
    pub observed_parent_height: u64,
    pub source_txid: Hash32,
    pub deposit_vout: u32,
    pub marker_vout: u32,
    /// SHA-256 of the exact consensus serialization of the referenced TxOut.
    pub output_sha256: Hash32,
    pub trader: XOnlyKey,
}

impl DepositEventV1 {
    pub const VERSION: u8 = 1;

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION
            || self.chain_id == [0; 32]
            || self.previous_root == [0; 32]
            || self.observed_sidechain_height == 0
            || self.observed_parent_height == 0
            || self.source_txid == [0; 32]
            || self.output_sha256 == [0; 32]
            || self.deposit_vout == self.marker_vout
            || XOnlyPublicKey::from_slice(&self.trader.0).is_err()
        {
            return Err(ProtocolError::InvalidDepositInbox);
        }
        Ok(())
    }

    pub fn event_hash(&self) -> Hash32 {
        canonical_hash("ECX/deposit-event/v1", self)
    }

    pub fn next_root(&self) -> Hash32 {
        let mut bytes = Vec::with_capacity(72);
        bytes.extend_from_slice(&self.previous_root);
        put_u64(&mut bytes, self.index);
        bytes.extend_from_slice(&self.event_hash());
        tagged_hash("ECX/deposit-inbox-step/v1", &bytes)
    }

    pub fn deadline(&self, inclusion_blocks: u32) -> Result<u64, ProtocolError> {
        if inclusion_blocks == 0 {
            return Err(ProtocolError::InvalidDepositInbox);
        }
        self.observed_parent_height
            .checked_add(u64::from(inclusion_blocks))
            .ok_or(ProtocolError::ArithmeticOverflow)
    }
}

impl CanonicalEncode for DepositEventV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.chain_id);
        put_u64(out, self.index);
        out.extend_from_slice(&self.previous_root);
        put_u64(out, self.observed_sidechain_height);
        put_u64(out, self.observed_parent_height);
        out.extend_from_slice(&self.source_txid);
        put_u32(out, self.deposit_vout);
        put_u32(out, self.marker_vout);
        out.extend_from_slice(&self.output_sha256);
        self.trader.encode_to(out);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DepositInboxStateV1 {
    pub head_root: Hash32,
    pub entry_count: u64,
    pub processed_root: Hash32,
    pub cursor: u64,
}

impl DepositInboxStateV1 {
    pub fn genesis(domain: Hash32, chain_id: Hash32) -> Result<Self, ProtocolError> {
        if domain == [0; 32] || chain_id == [0; 32] {
            return Err(ProtocolError::InvalidDepositInbox);
        }
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&domain);
        bytes[32..].copy_from_slice(&chain_id);
        let root = tagged_hash("ECX/deposit-inbox-genesis/v1", &bytes);
        Ok(Self {
            head_root: root,
            entry_count: 0,
            processed_root: root,
            cursor: 0,
        })
    }

    pub fn validate(self) -> Result<(), ProtocolError> {
        if self.head_root == [0; 32]
            || self.processed_root == [0; 32]
            || self.cursor > self.entry_count
            || (self.cursor == self.entry_count && self.processed_root != self.head_root)
        {
            return Err(ProtocolError::InvalidDepositInbox);
        }
        Ok(())
    }
}

impl CanonicalEncode for DepositInboxStateV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.head_root);
        put_u64(out, self.entry_count);
        out.extend_from_slice(&self.processed_root);
        put_u64(out, self.cursor);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DepositInboxTransitionV1 {
    /// Complete suffix from the previous cursor through the new source head.
    pub pending_entries: Vec<DepositEventV1>,
    pub consumed_count: u32,
}

impl DepositInboxTransitionV1 {
    pub fn verify(
        &self,
        chain_id: Hash32,
        previous: DepositInboxStateV1,
        next: DepositInboxStateV1,
        parent_height: u64,
        inclusion_blocks: u32,
    ) -> Result<bool, ProtocolError> {
        previous.validate()?;
        next.validate()?;
        let consumed =
            usize::try_from(self.consumed_count).map_err(|_| ProtocolError::ArithmeticOverflow)?;
        if chain_id == [0; 32]
            || consumed > self.pending_entries.len()
            || next.entry_count < previous.entry_count
            || next.cursor < previous.cursor
        {
            return Err(ProtocolError::InvalidDepositInbox);
        }

        let mut root = previous.processed_root;
        let mut index = previous.cursor;
        let consumed_end = index
            .checked_add(u64::from(self.consumed_count))
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        let mut root_after_consumed = root;
        let mut observed_previous_head = previous.cursor == previous.entry_count;
        let mut last_sidechain_height = 0u64;
        let mut last_parent_height = 0u64;
        let mut consumed_overdue = false;

        for (offset, entry) in self.pending_entries.iter().enumerate() {
            entry.validate()?;
            if entry.chain_id != chain_id
                || entry.index != index
                || entry.previous_root != root
                || (last_sidechain_height != 0
                    && entry.observed_sidechain_height < last_sidechain_height)
                || (last_parent_height != 0 && entry.observed_parent_height < last_parent_height)
            {
                return Err(ProtocolError::InvalidDepositInbox);
            }
            if offset < consumed {
                consumed_overdue |= parent_height >= entry.deadline(inclusion_blocks)?;
            }
            root = entry.next_root();
            index = index
                .checked_add(1)
                .ok_or(ProtocolError::ArithmeticOverflow)?;
            last_sidechain_height = entry.observed_sidechain_height;
            last_parent_height = entry.observed_parent_height;
            if index == consumed_end {
                root_after_consumed = root;
            }
            if index == previous.entry_count {
                if root != previous.head_root {
                    return Err(ProtocolError::InvalidDepositInbox);
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
            return Err(ProtocolError::InvalidDepositInbox);
        }
        if self.pending_entries.get(consumed).is_some_and(|entry| {
            entry
                .deadline(inclusion_blocks)
                .map(|deadline| parent_height >= deadline)
                .unwrap_or(true)
        }) {
            return Err(ProtocolError::DepositDeadline);
        }
        Ok(consumed_overdue)
    }

    pub fn consumed(&self) -> Result<&[DepositEventV1], ProtocolError> {
        let count =
            usize::try_from(self.consumed_count).map_err(|_| ProtocolError::ArithmeticOverflow)?;
        self.pending_entries
            .get(..count)
            .ok_or(ProtocolError::InvalidDepositInbox)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_TRADER_XONLY: [u8; 32] = [
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
        0x17, 0x98,
    ];

    fn event(index: u64, previous_root: Hash32, parent_height: u64) -> DepositEventV1 {
        DepositEventV1 {
            version: 1,
            chain_id: [1; 32],
            index,
            previous_root,
            observed_sidechain_height: 10 + index,
            observed_parent_height: parent_height,
            source_txid: [3 + index as u8; 32],
            deposit_vout: 0,
            marker_vout: 1,
            output_sha256: [5 + index as u8; 32],
            trader: XOnlyKey(VALID_TRADER_XONLY),
        }
    }

    #[test]
    fn marker_and_ordered_inbox_are_canonical() {
        let marker = DepositMarkerV1 {
            chain_id: [1; 32],
            deposit_vout: 2,
            trader: XOnlyKey(VALID_TRADER_XONLY),
        };
        let bytes = marker.payload_bytes().unwrap();
        assert_eq!(bytes.len(), DEPOSIT_MARKER_LEN);
        assert_eq!(DepositMarkerV1::decode_payload(&bytes).unwrap(), marker);

        let previous = DepositInboxStateV1::genesis([2; 32], [1; 32]).unwrap();
        let first = event(0, previous.head_root, 100);
        let next = DepositInboxStateV1 {
            head_root: first.next_root(),
            entry_count: 1,
            processed_root: first.next_root(),
            cursor: 1,
        };
        let transition = DepositInboxTransitionV1 {
            pending_entries: vec![first],
            consumed_count: 1,
        };
        assert!(!transition.verify([1; 32], previous, next, 101, 6).unwrap());
    }

    #[test]
    fn marker_accepts_a_valid_secp256k1_xonly_key() {
        let marker = DepositMarkerV1 {
            chain_id: [1; 32],
            deposit_vout: 2,
            trader: XOnlyKey(VALID_TRADER_XONLY),
        };

        let payload = marker.payload_bytes().unwrap();
        assert_eq!(DepositMarkerV1::decode_payload(&payload).unwrap(), marker);
    }

    #[test]
    fn marker_and_event_reject_non_curve_xonly_key() {
        let invalid_key = [0xff; 32];
        assert!(XOnlyPublicKey::from_slice(&invalid_key).is_err());

        let mut payload = Vec::with_capacity(DEPOSIT_MARKER_LEN);
        payload.extend_from_slice(&DEPOSIT_MARKER_MAGIC);
        put_u8(&mut payload, DEPOSIT_MARKER_VERSION);
        payload.extend_from_slice(&[1; 32]);
        put_u32(&mut payload, 2);
        payload.extend_from_slice(&invalid_key);
        assert_eq!(
            DepositMarkerV1::decode_payload(&payload),
            Err(ProtocolError::InvalidDepositInbox)
        );

        let previous = DepositInboxStateV1::genesis([2; 32], [1; 32]).unwrap();
        let mut invalid_event = event(0, previous.head_root, 100);
        invalid_event.trader = XOnlyKey(invalid_key);
        assert_eq!(
            invalid_event.validate(),
            Err(ProtocolError::InvalidDepositInbox)
        );
    }

    #[test]
    fn overdue_deposit_cannot_be_skipped() {
        let previous = DepositInboxStateV1::genesis([2; 32], [1; 32]).unwrap();
        let first = event(0, previous.head_root, 100);
        let next = DepositInboxStateV1 {
            head_root: first.next_root(),
            entry_count: 1,
            processed_root: previous.processed_root,
            cursor: 0,
        };
        let transition = DepositInboxTransitionV1 {
            pending_entries: vec![first],
            consumed_count: 0,
        };
        assert_eq!(
            transition.verify([1; 32], previous, next, 106, 6),
            Err(ProtocolError::DepositDeadline)
        );
    }
}
