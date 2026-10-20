use crate::codec::{put_u64, put_u8, CanonicalEncode};
use crate::deposit_inbox::DepositInboxStateV1;
use crate::forced::ForcedInboxStateV1;
use crate::hash::{canonical_hash, tagged_hash, Hash32};
use crate::merkle::{KeyedCommitment, MerkleTree};
use crate::order::{OrderId, Side};
use crate::types::{Amount, MarketId, Position, Price, Quantity, XOnlyKey, ECX_USDD_MARKET};
use crate::ProtocolError;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AccountLeaf {
    pub version: u8,
    pub trader: XOnlyKey,
    /// Next order/withdrawal nonce accepted for this account.
    pub account_nonce: u64,
    pub collateral: Amount,
    pub cumulative_realized_pnl: Amount,
    pub salt: Hash32,
}

impl AccountLeaf {
    pub const VERSION: u8 = 1;

    pub fn key(&self) -> Hash32 {
        tagged_hash("ECX/account-key/v1", &self.trader.0)
    }

    pub fn commitment(&self) -> Hash32 {
        canonical_hash("ECX/private-account-leaf/v1", self)
    }

    pub fn keyed_commitment(&self) -> KeyedCommitment {
        KeyedCommitment {
            key: self.key(),
            commitment: self.commitment(),
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION {
            return Err(ProtocolError::UnsupportedVersion);
        }
        if self.collateral.0 < 0 {
            return Err(ProtocolError::InsufficientCollateral);
        }
        if self.salt == [0; 32] {
            return Err(ProtocolError::ZeroSalt);
        }
        Ok(())
    }
}

impl CanonicalEncode for AccountLeaf {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        self.trader.encode_to(out);
        put_u64(out, self.account_nonce);
        self.collateral.encode_to(out);
        self.cumulative_realized_pnl.encode_to(out);
        out.extend_from_slice(&self.salt);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PositionLeaf {
    pub version: u8,
    pub trader: XOnlyKey,
    pub market: MarketId,
    pub position: Position,
    pub isolated_margin: Amount,
    pub salt: Hash32,
}

impl PositionLeaf {
    pub const VERSION: u8 = 1;

    pub fn key(&self) -> Hash32 {
        let mut bytes = Vec::with_capacity(48);
        self.trader.encode_to(&mut bytes);
        self.market.encode_to(&mut bytes);
        tagged_hash("ECX/position-key/v1", &bytes)
    }

    pub fn commitment(&self) -> Hash32 {
        canonical_hash("ECX/private-position-leaf/v1", self)
    }

    pub fn keyed_commitment(&self) -> KeyedCommitment {
        KeyedCommitment {
            key: self.key(),
            commitment: self.commitment(),
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION {
            return Err(ProtocolError::UnsupportedVersion);
        }
        self.market.validate()?;
        self.position.validate()?;
        // Protocol v1 is cross-margin only. Keeping this committed field at
        // zero prevents wallets or provers from treating an otherwise unused
        // value as spendable collateral under a different risk interpretation.
        if self.isolated_margin != Amount(0) {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        if self.salt == [0; 32] {
            return Err(ProtocolError::ZeroSalt);
        }
        Ok(())
    }
}

impl CanonicalEncode for PositionLeaf {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        self.trader.encode_to(out);
        self.market.encode_to(out);
        self.position.encode_to(out);
        self.isolated_margin.encode_to(out);
        out.extend_from_slice(&self.salt);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OpenOrderLeaf {
    pub version: u8,
    pub order_id: OrderId,
    pub trader: XOnlyKey,
    pub market: MarketId,
    pub side: Side,
    pub limit_price: Price,
    pub remaining_quantity: Quantity,
    /// Global matcher receipt sequence used as the time-priority tiebreaker.
    pub received_sequence: u64,
    pub expires_at_height: u64,
    pub salt: Hash32,
}

impl OpenOrderLeaf {
    pub const VERSION: u8 = 1;

    pub fn key(&self) -> Hash32 {
        self.order_id
    }

    pub fn commitment(&self) -> Hash32 {
        canonical_hash("ECX/private-open-order-leaf/v1", self)
    }

    pub fn keyed_commitment(&self) -> KeyedCommitment {
        KeyedCommitment {
            key: self.key(),
            commitment: self.commitment(),
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION {
            return Err(ProtocolError::UnsupportedVersion);
        }
        self.market.validate()?;
        Price::new(self.limit_price.get())?;
        Quantity::new(self.remaining_quantity.get())?;
        if self.salt == [0; 32] {
            return Err(ProtocolError::ZeroSalt);
        }
        Ok(())
    }
}

impl CanonicalEncode for OpenOrderLeaf {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.order_id);
        self.trader.encode_to(out);
        self.market.encode_to(out);
        put_u8(out, self.side as u8);
        self.limit_price.encode_to(out);
        self.remaining_quantity.encode_to(out);
        put_u64(out, self.received_sequence);
        put_u64(out, self.expires_at_height);
        out.extend_from_slice(&self.salt);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StateRoots {
    pub accounts: Hash32,
    pub positions: Hash32,
    pub open_orders: Hash32,
    pub deposit_nullifiers: Hash32,
    pub withdrawal_nullifiers: Hash32,
    /// Receipts commit to accepted order priority without publishing order bodies.
    pub order_receipts: Hash32,
}

impl StateRoots {
    pub fn from_private_state(
        accounts: &[AccountLeaf],
        positions: &[PositionLeaf],
        open_orders: &[OpenOrderLeaf],
        deposit_ids: &[Hash32],
        withdrawal_ids: &[Hash32],
        order_receipts: Hash32,
    ) -> Result<Self, ProtocolError> {
        for account in accounts {
            account.validate()?;
        }
        for position in positions {
            position.validate()?;
        }
        for order in open_orders {
            order.validate()?;
        }
        Ok(Self {
            accounts: MerkleTree::from_keyed(
                accounts.iter().map(AccountLeaf::keyed_commitment).collect(),
            )?
            .root(),
            positions: MerkleTree::from_keyed(
                positions
                    .iter()
                    .map(PositionLeaf::keyed_commitment)
                    .collect(),
            )?
            .root(),
            open_orders: MerkleTree::from_keyed(
                open_orders
                    .iter()
                    .map(OpenOrderLeaf::keyed_commitment)
                    .collect(),
            )?
            .root(),
            deposit_nullifiers: nullifier_root("ECX/deposit-nullifier/v1", deposit_ids)?,
            withdrawal_nullifiers: nullifier_root("ECX/withdrawal-nullifier/v1", withdrawal_ids)?,
            order_receipts,
        })
    }
}

impl CanonicalEncode for StateRoots {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.accounts);
        out.extend_from_slice(&self.positions);
        out.extend_from_slice(&self.open_orders);
        out.extend_from_slice(&self.deposit_nullifiers);
        out.extend_from_slice(&self.withdrawal_nullifiers);
        out.extend_from_slice(&self.order_receipts);
    }
}

fn nullifier_root(tag: &str, ids: &[Hash32]) -> Result<Hash32, ProtocolError> {
    let mut commitments = Vec::with_capacity(ids.len());
    for id in ids {
        commitments.push(KeyedCommitment {
            key: *id,
            commitment: tagged_hash(tag, id),
        });
    }
    Ok(MerkleTree::from_keyed(commitments)?.root())
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExchangeState {
    pub protocol_version: u8,
    pub chain_id: Hash32,
    pub market: MarketId,
    pub sequence: u64,
    pub last_processed_height: u64,
    pub mark_price: Price,
    pub funding_index: i128,
    pub total_deposits: Amount,
    pub total_withdrawals: Amount,
    pub insurance_fund: Amount,
    pub fee_pool: Amount,
    /// Last centrally sequenced matcher command consumed by the proof.
    pub matcher_sequence: u64,
    pub matcher_receipt_hash: Hash32,
    /// Ordered on-chain escape hatch. The public covenant separately exposes
    /// `head_root`; `processed_root` and `cursor` remain privacy-preserving
    /// transition state while still being committed by `state_root()`.
    pub forced_inbox: ForcedInboxStateV1,
    /// Consensus-derived confidential collateral deposits waiting for proof
    /// opening and ledger credit.
    pub deposit_inbox: DepositInboxStateV1,
    pub roots: StateRoots,
}

impl ExchangeState {
    pub const VERSION: u8 = 4;

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.protocol_version != Self::VERSION {
            return Err(ProtocolError::UnsupportedVersion);
        }
        if self.market != ECX_USDD_MARKET {
            return Err(ProtocolError::InvalidMarket);
        }
        if self.total_deposits.0 < 0
            || self.total_withdrawals.0 < 0
            || self.insurance_fund.0 < 0
            || self.fee_pool.0 < 0
            || self.matcher_receipt_hash == [0; 32]
        {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        self.forced_inbox.validate()?;
        self.deposit_inbox.validate()?;
        Ok(())
    }

    pub fn state_root(&self) -> Hash32 {
        canonical_hash("ECX/exchange-state/v4", self)
    }

    pub fn commitment(&self) -> StateCommitment {
        StateCommitment {
            sequence: self.sequence,
            root: self.state_root(),
        }
    }
}

impl CanonicalEncode for ExchangeState {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.protocol_version);
        out.extend_from_slice(&self.chain_id);
        self.market.encode_to(out);
        put_u64(out, self.sequence);
        put_u64(out, self.last_processed_height);
        self.mark_price.encode_to(out);
        out.extend_from_slice(&self.funding_index.to_be_bytes());
        self.total_deposits.encode_to(out);
        self.total_withdrawals.encode_to(out);
        self.insurance_fund.encode_to(out);
        self.fee_pool.encode_to(out);
        put_u64(out, self.matcher_sequence);
        out.extend_from_slice(&self.matcher_receipt_hash);
        self.forced_inbox.encode_to(out);
        self.deposit_inbox.encode_to(out);
        self.roots.encode_to(out);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StateCommitment {
    pub sequence: u64,
    pub root: Hash32,
}

impl CanonicalEncode for StateCommitment {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u64(out, self.sequence);
        out.extend_from_slice(&self.root);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::empty_hash;
    use crate::types::PRICE_SCALE;

    fn account(salt: u8) -> AccountLeaf {
        AccountLeaf {
            version: 1,
            trader: XOnlyKey([2; 32]),
            account_nonce: 0,
            collateral: Amount(1_000),
            cumulative_realized_pnl: Amount(0),
            salt: [salt; 32],
        }
    }

    #[test]
    fn fresh_salt_changes_private_commitment() {
        assert_ne!(account(1).commitment(), account(2).commitment());
        assert_eq!(account(1).key(), account(2).key());
    }

    #[test]
    fn zero_salt_is_rejected() {
        assert_eq!(account(0).validate(), Err(ProtocolError::ZeroSalt));
    }

    #[test]
    fn root_is_deterministic_under_input_reordering() {
        let mut second = account(2);
        second.trader = XOnlyKey([3; 32]);
        let a = StateRoots::from_private_state(
            &[account(1), second.clone()],
            &[],
            &[],
            &[],
            &[],
            empty_hash(),
        )
        .unwrap();
        let b =
            StateRoots::from_private_state(&[second, account(1)], &[], &[], &[], &[], empty_hash())
                .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn state_sequence_is_committed() {
        let roots = StateRoots::from_private_state(&[], &[], &[], &[], &[], empty_hash()).unwrap();
        let state = ExchangeState {
            protocol_version: ExchangeState::VERSION,
            chain_id: [9; 32],
            market: ECX_USDD_MARKET,
            sequence: 1,
            last_processed_height: 100,
            mark_price: Price::new(PRICE_SCALE).unwrap(),
            funding_index: 0,
            total_deposits: Amount(0),
            total_withdrawals: Amount(0),
            insurance_fund: Amount(0),
            fee_pool: Amount(0),
            matcher_sequence: 0,
            matcher_receipt_hash: [12; 32],
            forced_inbox: ForcedInboxStateV1::genesis([13; 32], [9; 32]).unwrap(),
            deposit_inbox: DepositInboxStateV1::genesis([14; 32], [9; 32]).unwrap(),
            roots,
        };
        let mut next = state.clone();
        next.sequence += 1;
        assert_ne!(state.state_root(), next.state_root());
    }
}
