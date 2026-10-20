//! Fresh lifetime-safe signed wire formats for the incremental successor.
//!
//! V1 action bytes and signature domains remain unchanged. These formats use
//! direct big-endian `u128` account nonces and distinct version-2 domains, so a
//! V1 signature cannot authorize a successor action and no high nonce bits are
//! hidden outside the signed canonical record.

use secp256k1::{schnorr, Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};

use crate::codec::{put_i128, put_u128, put_u32, put_u64, put_u8, CanonicalEncode, Decoder};
use crate::hash::{canonical_hash, Hash32};
use crate::merkle::ordered_root;
use crate::order::{OrderFlags, OrderId, Side, Signature64, TimeInForce};
use crate::types::{Amount, MarketId, Price, Quantity, XOnlyKey, ECX_USDD_MARKET};
use crate::ProtocolError;

pub const SUCCESSOR_LIMIT_ORDER_ENCODED_LEN_V2: usize = 152;
pub const SUCCESSOR_SIGNED_LIMIT_ORDER_ENCODED_LEN_V2: usize =
    SUCCESSOR_LIMIT_ORDER_ENCODED_LEN_V2 + 64;
pub const SUCCESSOR_CANCEL_ORDER_ENCODED_LEN_V2: usize = 145;
pub const SUCCESSOR_SIGNED_CANCEL_ORDER_ENCODED_LEN_V2: usize =
    SUCCESSOR_CANCEL_ORDER_ENCODED_LEN_V2 + 64;
pub const SUCCESSOR_WITHDRAWAL_REQUEST_ENCODED_LEN_V2: usize = 137;
pub const SUCCESSOR_SIGNED_WITHDRAWAL_REQUEST_ENCODED_LEN_V2: usize =
    SUCCESSOR_WITHDRAWAL_REQUEST_ENCODED_LEN_V2 + 64;
pub const SUCCESSOR_TRADE_MATCH_ENCODED_LEN_V2: usize = 193;

pub(crate) fn sign_digest(
    digest: Hash32,
    expected: XOnlyKey,
    secret_key: &SecretKey,
) -> Result<Signature64, ProtocolError> {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, secret_key);
    let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
    if xonly.serialize() != expected.0 {
        return Err(ProtocolError::SigningKeyMismatch);
    }
    let message =
        Message::from_digest_slice(&digest).map_err(|_| ProtocolError::InvalidSignature)?;
    Ok(Signature64(
        *secp.sign_schnorr_no_aux_rand(&message, &keypair).as_ref(),
    ))
}

pub(crate) fn verify_digest(
    digest: Hash32,
    signer: XOnlyKey,
    signature: Signature64,
) -> Result<(), ProtocolError> {
    let key = XOnlyPublicKey::from_slice(&signer.0).map_err(|_| ProtocolError::InvalidSignature)?;
    let signature = schnorr::Signature::from_slice(&signature.0)
        .map_err(|_| ProtocolError::InvalidSignature)?;
    let message =
        Message::from_digest_slice(&digest).map_err(|_| ProtocolError::InvalidSignature)?;
    Secp256k1::verification_only()
        .verify_schnorr(&signature, &message, &key)
        .map_err(|_| ProtocolError::InvalidSignature)
}

fn decode_side(value: u8) -> Result<Side, ProtocolError> {
    match value {
        0 => Ok(Side::Buy),
        1 => Ok(Side::Sell),
        _ => Err(ProtocolError::NonCanonicalEncoding),
    }
}

fn decode_time_in_force(value: u8) -> Result<TimeInForce, ProtocolError> {
    match value {
        0 => Ok(TimeInForce::GoodTilHeight),
        1 => Ok(TimeInForce::ImmediateOrCancel),
        _ => Err(ProtocolError::NonCanonicalEncoding),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorLimitOrderV2 {
    pub version: u8,
    pub chain_id: Hash32,
    pub market: MarketId,
    pub trader: XOnlyKey,
    pub side: Side,
    pub time_in_force: TimeInForce,
    pub flags: OrderFlags,
    pub limit_price: Price,
    pub quantity: Quantity,
    pub client_order_id: [u8; 16],
    pub max_fee_bps: u32,
    pub nonce: u128,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
}

impl SuccessorLimitOrderV2 {
    pub const VERSION: u8 = 2;

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION {
            return Err(ProtocolError::UnsupportedVersion);
        }
        if !matches!(
            self.time_in_force,
            TimeInForce::GoodTilHeight | TimeInForce::ImmediateOrCancel
        ) {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        self.market.validate()?;
        Price::new(self.limit_price.get())?;
        Quantity::new(self.quantity.get())?;
        if OrderFlags::from_bits(self.flags.bits()).is_none() {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        if self.max_fee_bps > 10_000 {
            return Err(ProtocolError::InvalidRate);
        }
        if self.expires_at_height < self.valid_from_height {
            return Err(ProtocolError::OrderNotLive);
        }
        Ok(())
    }

    pub fn signing_digest(&self) -> Hash32 {
        canonical_hash("ECX/incremental-limit-order/v2-u128", self)
    }

    pub fn order_id(&self) -> OrderId {
        canonical_hash("ECX/incremental-order-id/v2-u128", self)
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        height >= self.valid_from_height && height <= self.expires_at_height
    }

    pub fn decode_fixed(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != SUCCESSOR_LIMIT_ORDER_ENCODED_LEN_V2 {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        let mut decoder = Decoder::new(bytes);
        let value = Self {
            version: decoder.u8()?,
            chain_id: decoder.take()?,
            market: MarketId(decoder.take()?),
            trader: XOnlyKey(decoder.take()?),
            side: decode_side(decoder.u8()?)?,
            time_in_force: decode_time_in_force(decoder.u8()?)?,
            flags: OrderFlags::from_bits(decoder.u8()?)
                .ok_or(ProtocolError::NonCanonicalEncoding)?,
            limit_price: Price::new(decoder.u64()?)?,
            quantity: Quantity::new(decoder.u64()?)?,
            client_order_id: decoder.take()?,
            max_fee_bps: decoder.u32()?,
            nonce: u128::from_be_bytes(decoder.take()?),
            valid_from_height: decoder.u64()?,
            expires_at_height: decoder.u64()?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }
}

impl CanonicalEncode for SuccessorLimitOrderV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.chain_id);
        self.market.encode_to(out);
        self.trader.encode_to(out);
        put_u8(out, self.side as u8);
        put_u8(out, self.time_in_force as u8);
        put_u8(out, self.flags.bits());
        self.limit_price.encode_to(out);
        self.quantity.encode_to(out);
        out.extend_from_slice(&self.client_order_id);
        put_u32(out, self.max_fee_bps);
        put_u128(out, self.nonce);
        put_u64(out, self.valid_from_height);
        put_u64(out, self.expires_at_height);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorSignedLimitOrderV2 {
    pub order: SuccessorLimitOrderV2,
    pub signature: Signature64,
}

impl SuccessorSignedLimitOrderV2 {
    pub fn sign(order: SuccessorLimitOrderV2, key: &SecretKey) -> Result<Self, ProtocolError> {
        order.validate()?;
        let signature = sign_digest(order.signing_digest(), order.trader, key)?;
        Ok(Self { order, signature })
    }

    pub fn verify(&self) -> Result<(), ProtocolError> {
        self.order.validate()?;
        verify_digest(
            self.order.signing_digest(),
            self.order.trader,
            self.signature,
        )
    }

    pub fn order_id(&self) -> OrderId {
        self.order.order_id()
    }

    pub fn decode_fixed(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != SUCCESSOR_SIGNED_LIMIT_ORDER_ENCODED_LEN_V2 {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        let order =
            SuccessorLimitOrderV2::decode_fixed(&bytes[..SUCCESSOR_LIMIT_ORDER_ENCODED_LEN_V2])?;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[SUCCESSOR_LIMIT_ORDER_ENCODED_LEN_V2..]);
        Ok(Self {
            order,
            signature: Signature64(signature),
        })
    }
}

impl CanonicalEncode for SuccessorSignedLimitOrderV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.order.encode_to(out);
        self.signature.encode_to(out);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorCancelOrderV2 {
    pub version: u8,
    pub chain_id: Hash32,
    pub market: MarketId,
    pub trader: XOnlyKey,
    pub order_id: OrderId,
    pub nonce: u128,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
}

impl SuccessorCancelOrderV2 {
    pub const VERSION: u8 = 2;

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION {
            return Err(ProtocolError::UnsupportedVersion);
        }
        self.market.validate()?;
        if self.expires_at_height < self.valid_from_height {
            return Err(ProtocolError::OrderNotLive);
        }
        Ok(())
    }

    pub fn signing_digest(&self) -> Hash32 {
        canonical_hash("ECX/incremental-cancel-order/v2-u128", self)
    }

    pub fn cancel_id(&self) -> Hash32 {
        canonical_hash("ECX/incremental-cancel-id/v2-u128", self)
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        height >= self.valid_from_height && height <= self.expires_at_height
    }

    pub fn decode_fixed(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != SUCCESSOR_CANCEL_ORDER_ENCODED_LEN_V2 {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        let mut decoder = Decoder::new(bytes);
        let value = Self {
            version: decoder.u8()?,
            chain_id: decoder.take()?,
            market: MarketId(decoder.take()?),
            trader: XOnlyKey(decoder.take()?),
            order_id: decoder.take()?,
            nonce: u128::from_be_bytes(decoder.take()?),
            valid_from_height: decoder.u64()?,
            expires_at_height: decoder.u64()?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }
}

impl CanonicalEncode for SuccessorCancelOrderV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.chain_id);
        self.market.encode_to(out);
        self.trader.encode_to(out);
        out.extend_from_slice(&self.order_id);
        put_u128(out, self.nonce);
        put_u64(out, self.valid_from_height);
        put_u64(out, self.expires_at_height);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorSignedCancelOrderV2 {
    pub cancel: SuccessorCancelOrderV2,
    pub signature: Signature64,
}

impl SuccessorSignedCancelOrderV2 {
    pub fn sign(cancel: SuccessorCancelOrderV2, key: &SecretKey) -> Result<Self, ProtocolError> {
        cancel.validate()?;
        let signature = sign_digest(cancel.signing_digest(), cancel.trader, key)?;
        Ok(Self { cancel, signature })
    }

    pub fn verify(&self) -> Result<(), ProtocolError> {
        self.cancel.validate()?;
        verify_digest(
            self.cancel.signing_digest(),
            self.cancel.trader,
            self.signature,
        )
    }

    pub fn decode_fixed(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != SUCCESSOR_SIGNED_CANCEL_ORDER_ENCODED_LEN_V2 {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        let cancel =
            SuccessorCancelOrderV2::decode_fixed(&bytes[..SUCCESSOR_CANCEL_ORDER_ENCODED_LEN_V2])?;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[SUCCESSOR_CANCEL_ORDER_ENCODED_LEN_V2..]);
        Ok(Self {
            cancel,
            signature: Signature64(signature),
        })
    }
}

impl CanonicalEncode for SuccessorSignedCancelOrderV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.cancel.encode_to(out);
        self.signature.encode_to(out);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorWithdrawalRequestV2 {
    pub version: u8,
    pub chain_id: Hash32,
    pub trader: XOnlyKey,
    pub nonce: u128,
    pub amount: u64,
    pub destination_script_hash: Hash32,
    pub requested_height: u64,
    pub not_before_height: u64,
}

impl SuccessorWithdrawalRequestV2 {
    pub const VERSION: u8 = 2;

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION {
            return Err(ProtocolError::UnsupportedVersion);
        }
        if self.amount == 0 {
            return Err(ProtocolError::InvalidQuantity);
        }
        if self.not_before_height < self.requested_height {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        Ok(())
    }

    pub fn signing_digest(&self) -> Hash32 {
        canonical_hash("ECX/incremental-withdrawal-request/v2-u128", self)
    }

    pub fn request_id(&self) -> Hash32 {
        canonical_hash("ECX/incremental-withdrawal-id/v2-u128", self)
    }

    pub fn decode_fixed(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != SUCCESSOR_WITHDRAWAL_REQUEST_ENCODED_LEN_V2 {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        let mut decoder = Decoder::new(bytes);
        let value = Self {
            version: decoder.u8()?,
            chain_id: decoder.take()?,
            trader: XOnlyKey(decoder.take()?),
            nonce: u128::from_be_bytes(decoder.take()?),
            amount: decoder.u64()?,
            destination_script_hash: decoder.take()?,
            requested_height: decoder.u64()?,
            not_before_height: decoder.u64()?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }
}

impl CanonicalEncode for SuccessorWithdrawalRequestV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.chain_id);
        self.trader.encode_to(out);
        put_u128(out, self.nonce);
        put_u64(out, self.amount);
        out.extend_from_slice(&self.destination_script_hash);
        put_u64(out, self.requested_height);
        put_u64(out, self.not_before_height);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorSignedWithdrawalRequestV2 {
    pub request: SuccessorWithdrawalRequestV2,
    pub signature: Signature64,
}

impl SuccessorSignedWithdrawalRequestV2 {
    pub fn sign(
        request: SuccessorWithdrawalRequestV2,
        key: &SecretKey,
    ) -> Result<Self, ProtocolError> {
        request.validate()?;
        let signature = sign_digest(request.signing_digest(), request.trader, key)?;
        Ok(Self { request, signature })
    }

    pub fn verify(&self) -> Result<(), ProtocolError> {
        self.request.validate()?;
        verify_digest(
            self.request.signing_digest(),
            self.request.trader,
            self.signature,
        )
    }

    pub fn decode_fixed(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != SUCCESSOR_SIGNED_WITHDRAWAL_REQUEST_ENCODED_LEN_V2 {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        let request = SuccessorWithdrawalRequestV2::decode_fixed(
            &bytes[..SUCCESSOR_WITHDRAWAL_REQUEST_ENCODED_LEN_V2],
        )?;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[SUCCESSOR_WITHDRAWAL_REQUEST_ENCODED_LEN_V2..]);
        Ok(Self {
            request,
            signature: Signature64(signature),
        })
    }
}

impl CanonicalEncode for SuccessorSignedWithdrawalRequestV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.request.encode_to(out);
        self.signature.encode_to(out);
    }
}

pub fn successor_withdrawal_batch_root_v2(
    withdrawals: &[SuccessorSignedWithdrawalRequestV2],
) -> Hash32 {
    let ids: Vec<Hash32> = withdrawals
        .iter()
        .map(|request| request.request.request_id())
        .collect();
    ordered_root("ECX/successor-withdrawal-batch/v2-u128", &ids)
}

/// Fresh matched-fill wire record for the incremental successor. Its
/// admission sequence is a direct `u128`; it is deliberately not convertible
/// to the finite V1 [`crate::TradeMatch`] because such a conversion would
/// silently discard reachable high sequence bits.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorTradeMatchV2 {
    pub sequence: u128,
    pub maker_order_id: OrderId,
    pub taker_order_id: OrderId,
    pub maker: XOnlyKey,
    pub taker: XOnlyKey,
    pub maker_side: Side,
    pub price: Price,
    pub quantity: Quantity,
    pub maker_fee: Amount,
    pub taker_fee: Amount,
}

impl SuccessorTradeMatchV2 {
    pub fn validate_orders(
        &self,
        maker: &SuccessorSignedLimitOrderV2,
        taker: &SuccessorSignedLimitOrderV2,
        height: u64,
    ) -> Result<(), ProtocolError> {
        maker.verify()?;
        taker.verify()?;
        if !maker.order.is_live_at(height) || !taker.order.is_live_at(height) {
            return Err(ProtocolError::OrderNotLive);
        }
        if self.sequence == 0
            || maker.order.market != ECX_USDD_MARKET
            || maker.order.market != taker.order.market
            || maker.order.chain_id != taker.order.chain_id
            || maker.order.side == taker.order.side
            || self.maker_order_id != maker.order_id()
            || self.taker_order_id != taker.order_id()
            || self.maker != maker.order.trader
            || self.taker != taker.order.trader
            || self.maker_side != maker.order.side
            || self.price != maker.order.limit_price
        {
            return Err(ProtocolError::IncompatibleOrders);
        }
        let crosses = match maker.order.side {
            Side::Sell => taker.order.limit_price >= maker.order.limit_price,
            Side::Buy => taker.order.limit_price <= maker.order.limit_price,
        };
        if !crosses {
            return Err(ProtocolError::IncompatibleOrders);
        }
        if self.quantity.get() > maker.order.quantity.get()
            || self.quantity.get() > taker.order.quantity.get()
        {
            return Err(ProtocolError::ExcessFill);
        }
        Ok(())
    }

    pub fn match_id(&self) -> Hash32 {
        canonical_hash("ECX/incremental-trade-match/v2-u128", self)
    }

    pub fn decode_fixed(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != SUCCESSOR_TRADE_MATCH_ENCODED_LEN_V2 {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        let mut decoder = Decoder::new(bytes);
        let value = Self {
            sequence: u128::from_be_bytes(decoder.take()?),
            maker_order_id: decoder.take()?,
            taker_order_id: decoder.take()?,
            maker: XOnlyKey(decoder.take()?),
            taker: XOnlyKey(decoder.take()?),
            maker_side: decode_side(decoder.u8()?)?,
            price: Price::new(decoder.u64()?)?,
            quantity: Quantity::new(decoder.u64()?)?,
            maker_fee: Amount(i128::from_be_bytes(decoder.take()?)),
            taker_fee: Amount(i128::from_be_bytes(decoder.take()?)),
        };
        decoder.finish()?;
        if value.sequence == 0 {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        Ok(value)
    }
}

impl CanonicalEncode for SuccessorTradeMatchV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u128(out, self.sequence);
        out.extend_from_slice(&self.maker_order_id);
        out.extend_from_slice(&self.taker_order_id);
        self.maker.encode_to(out);
        self.taker.encode_to(out);
        put_u8(out, self.maker_side as u8);
        self.price.encode_to(out);
        self.quantity.encode_to(out);
        put_i128(out, self.maker_fee.0);
        put_i128(out, self.taker_fee.0);
    }
}

#[cfg(test)]
mod tests {
    use secp256k1::{Keypair, Secp256k1};

    use super::*;
    use crate::order::{LimitOrder, SignedLimitOrder};

    fn key() -> (SecretKey, XOnlyKey) {
        let secret = SecretKey::from_slice(&[42; 32]).unwrap();
        let pair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
        let (public, _) = XOnlyPublicKey::from_keypair(&pair);
        (secret, XOnlyKey(public.serialize()))
    }

    fn order(nonce: u128) -> SuccessorLimitOrderV2 {
        let (_, trader) = key();
        SuccessorLimitOrderV2 {
            version: SuccessorLimitOrderV2::VERSION,
            chain_id: [7; 32],
            market: crate::types::ECX_USDD_MARKET,
            trader,
            side: Side::Buy,
            time_in_force: TimeInForce::GoodTilHeight,
            flags: OrderFlags::NONE,
            limit_price: Price::new(100_000_000).unwrap(),
            quantity: Quantity::new(9).unwrap(),
            client_order_id: [8; 16],
            max_fee_bps: 5,
            nonce,
            valid_from_height: 10,
            expires_at_height: 20,
        }
    }

    #[test]
    fn successor_signed_actions_bind_full_u128_nonce_and_are_v1_domain_separate() {
        let (secret, trader) = key();
        let high_nonce = (1u128 << 96) + 17;
        let signed = SuccessorSignedLimitOrderV2::sign(order(high_nonce), &secret).unwrap();
        signed.verify().unwrap();
        assert_eq!(
            signed.canonical_bytes().len(),
            SUCCESSOR_SIGNED_LIMIT_ORDER_ENCODED_LEN_V2
        );
        assert_eq!(
            SuccessorLimitOrderV2::decode_fixed(
                &signed.canonical_bytes()[..SUCCESSOR_LIMIT_ORDER_ENCODED_LEN_V2]
            )
            .unwrap()
            .nonce,
            high_nonce
        );
        assert_eq!(
            SuccessorSignedLimitOrderV2::decode_fixed(&signed.canonical_bytes()).unwrap(),
            signed
        );
        let mut changed_high_bits = signed.clone();
        changed_high_bits.order.nonce ^= 1u128 << 96;
        assert_eq!(
            changed_high_bits.verify(),
            Err(ProtocolError::InvalidSignature)
        );

        let v1 = SignedLimitOrder::sign(
            LimitOrder {
                version: LimitOrder::VERSION,
                chain_id: signed.order.chain_id,
                market: signed.order.market,
                trader,
                side: signed.order.side,
                time_in_force: signed.order.time_in_force,
                flags: signed.order.flags,
                limit_price: signed.order.limit_price,
                quantity: signed.order.quantity,
                client_order_id: signed.order.client_order_id,
                max_fee_bps: signed.order.max_fee_bps,
                nonce: 17,
                valid_from_height: signed.order.valid_from_height,
                expires_at_height: signed.order.expires_at_height,
            },
            &secret,
        )
        .unwrap();
        assert_ne!(v1.order_id(), signed.order_id());

        let cancel = SuccessorSignedCancelOrderV2::sign(
            SuccessorCancelOrderV2 {
                version: SuccessorCancelOrderV2::VERSION,
                chain_id: [7; 32],
                market: crate::types::ECX_USDD_MARKET,
                trader,
                order_id: signed.order_id(),
                nonce: high_nonce + 1,
                valid_from_height: 10,
                expires_at_height: 20,
            },
            &secret,
        )
        .unwrap();
        cancel.verify().unwrap();
        assert_eq!(
            cancel.canonical_bytes().len(),
            SUCCESSOR_SIGNED_CANCEL_ORDER_ENCODED_LEN_V2
        );
        assert_eq!(
            SuccessorSignedCancelOrderV2::decode_fixed(&cancel.canonical_bytes()).unwrap(),
            cancel
        );

        let withdrawal = SuccessorSignedWithdrawalRequestV2::sign(
            SuccessorWithdrawalRequestV2 {
                version: SuccessorWithdrawalRequestV2::VERSION,
                chain_id: [7; 32],
                trader,
                nonce: high_nonce + 2,
                amount: 3,
                destination_script_hash: [9; 32],
                requested_height: 10,
                not_before_height: 11,
            },
            &secret,
        )
        .unwrap();
        withdrawal.verify().unwrap();
        assert_eq!(
            withdrawal.canonical_bytes().len(),
            SUCCESSOR_SIGNED_WITHDRAWAL_REQUEST_ENCODED_LEN_V2
        );
        assert_eq!(
            SuccessorSignedWithdrawalRequestV2::decode_fixed(&withdrawal.canonical_bytes())
                .unwrap(),
            withdrawal
        );

        let taker = SuccessorSignedLimitOrderV2::sign(
            SuccessorLimitOrderV2 {
                side: Side::Sell,
                limit_price: Price::new(90_000_000).unwrap(),
                client_order_id: [10; 16],
                nonce: high_nonce + 3,
                ..order(high_nonce + 3)
            },
            &secret,
        )
        .unwrap();
        let trade = SuccessorTradeMatchV2 {
            sequence: high_nonce + 4,
            maker_order_id: signed.order_id(),
            taker_order_id: taker.order_id(),
            maker: signed.order.trader,
            taker: taker.order.trader,
            maker_side: signed.order.side,
            price: signed.order.limit_price,
            quantity: Quantity::new(3).unwrap(),
            maker_fee: Amount(0),
            taker_fee: Amount(1),
        };
        trade.validate_orders(&signed, &taker, 15).unwrap();
        assert_eq!(
            SuccessorTradeMatchV2::decode_fixed(&trade.canonical_bytes()).unwrap(),
            trade
        );
        let mut changed_sequence = trade.clone();
        changed_sequence.sequence ^= 1u128 << 96;
        assert_ne!(changed_sequence.match_id(), trade.match_id());

        for mut bytes in [
            signed.canonical_bytes(),
            cancel.canonical_bytes(),
            withdrawal.canonical_bytes(),
        ] {
            bytes.push(0);
            assert!(SuccessorSignedLimitOrderV2::decode_fixed(&bytes).is_err());
            assert!(SuccessorSignedCancelOrderV2::decode_fixed(&bytes).is_err());
            assert!(SuccessorSignedWithdrawalRequestV2::decode_fixed(&bytes).is_err());
        }
    }

    #[test]
    fn successor_order_rejects_noncanonical_legacy_fill_or_kill() {
        let (secret, _) = key();
        let mut unsupported = order((1u128 << 96) + 18);
        unsupported.time_in_force = TimeInForce::FillOrKill;
        assert_eq!(
            unsupported.validate(),
            Err(ProtocolError::NonCanonicalEncoding)
        );
        assert_eq!(
            SuccessorSignedLimitOrderV2::sign(unsupported, &secret),
            Err(ProtocolError::NonCanonicalEncoding)
        );
    }
}
