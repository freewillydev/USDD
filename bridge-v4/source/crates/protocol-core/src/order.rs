use core::fmt;

use secp256k1::{schnorr, Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};

use crate::codec::{put_i128, put_u32, put_u64, put_u8, CanonicalEncode, Decoder};
use crate::hash::{canonical_hash, Hash32};
use crate::types::{Amount, MarketId, Price, Quantity, XOnlyKey, ECX_USDD_MARKET};
use crate::ProtocolError;

pub type OrderId = Hash32;

pub const LIMIT_ORDER_ENCODED_LEN: usize = 144;
pub const SIGNED_ORDER_ENCODED_LEN: usize = LIMIT_ORDER_ENCODED_LEN + 64;
pub const CANCEL_ORDER_ENCODED_LEN: usize = 137;
pub const SIGNED_CANCEL_ENCODED_LEN: usize = CANCEL_ORDER_ENCODED_LEN + 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Side {
    Buy = 0,
    Sell = 1,
}

impl Side {
    pub const fn sign(self) -> i64 {
        match self {
            Self::Buy => 1,
            Self::Sell => -1,
        }
    }

    pub const fn opposite(self) -> Self {
        match self {
            Self::Buy => Self::Sell,
            Self::Sell => Self::Buy,
        }
    }

    fn decode(value: u8) -> Result<Self, ProtocolError> {
        match value {
            0 => Ok(Self::Buy),
            1 => Ok(Self::Sell),
            other => Err(ProtocolError::InvalidDiscriminant(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TimeInForce {
    GoodTilHeight = 0,
    ImmediateOrCancel = 1,
    FillOrKill = 2,
}

impl TimeInForce {
    fn decode(value: u8) -> Result<Self, ProtocolError> {
        match value {
            0 => Ok(Self::GoodTilHeight),
            1 => Ok(Self::ImmediateOrCancel),
            2 => Ok(Self::FillOrKill),
            other => Err(ProtocolError::InvalidDiscriminant(other)),
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OrderFlags(u8);

impl OrderFlags {
    pub const NONE: Self = Self(0);
    pub const REDUCE_ONLY: Self = Self(1 << 0);
    pub const POST_ONLY: Self = Self(1 << 1);
    const KNOWN: u8 = Self::REDUCE_ONLY.0 | Self::POST_ONLY.0;

    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !Self::KNOWN == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl fmt::Debug for OrderFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("OrderFlags").field(&self.0).finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LimitOrder {
    pub version: u8,
    pub chain_id: Hash32,
    pub market: MarketId,
    pub trader: XOnlyKey,
    pub side: Side,
    pub time_in_force: TimeInForce,
    pub flags: OrderFlags,
    pub limit_price: Price,
    pub quantity: Quantity,
    /// Opaque wallet-generated idempotency key; fixed width for proof use.
    pub client_order_id: [u8; 16],
    /// The signer rejects any batch whose fee schedule exceeds this cap.
    pub max_fee_bps: u32,
    /// Per-account strictly increasing nonce, consumed even on cancellation.
    pub nonce: u64,
    pub valid_from_height: u64,
    /// Inclusive expiry; use `u64::MAX` for an order with no practical expiry.
    pub expires_at_height: u64,
}

impl LimitOrder {
    pub const VERSION: u8 = 1;

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION {
            return Err(ProtocolError::UnsupportedVersion);
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
        canonical_hash("ECX/limit-order/v1", self)
    }

    pub fn order_id(&self) -> OrderId {
        canonical_hash("ECX/order-id/v1", self)
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        height >= self.valid_from_height && height <= self.expires_at_height
    }

    pub fn decode_fixed(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != LIMIT_ORDER_ENCODED_LEN {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        let mut decoder = Decoder::new(bytes);
        let version = decoder.u8()?;
        let chain_id = decoder.take()?;
        let market = MarketId(decoder.take()?);
        let trader = XOnlyKey(decoder.take()?);
        let side = Side::decode(decoder.u8()?)?;
        let time_in_force = TimeInForce::decode(decoder.u8()?)?;
        let flags =
            OrderFlags::from_bits(decoder.u8()?).ok_or(ProtocolError::NonCanonicalEncoding)?;
        let limit_price = Price::new(decoder.u64()?)?;
        let quantity = Quantity::new(decoder.u64()?)?;
        let client_order_id = decoder.take()?;
        let max_fee_bps = decoder.u32()?;
        let nonce = decoder.u64()?;
        let valid_from_height = decoder.u64()?;
        let expires_at_height = decoder.u64()?;
        decoder.finish()?;
        let order = Self {
            version,
            chain_id,
            market,
            trader,
            side,
            time_in_force,
            flags,
            limit_price,
            quantity,
            client_order_id,
            max_fee_bps,
            nonce,
            valid_from_height,
            expires_at_height,
        };
        order.validate()?;
        Ok(order)
    }
}

impl CanonicalEncode for LimitOrder {
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
        put_u64(out, self.nonce);
        put_u64(out, self.valid_from_height);
        put_u64(out, self.expires_at_height);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature64(pub [u8; 64]);

impl fmt::Debug for Signature64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Signature64(<redacted>)")
    }
}

impl CanonicalEncode for Signature64 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Signature64 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Signature64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Signature64;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("exactly 64 signature bytes")
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value.len() != 64 {
                    return Err(E::invalid_length(value.len(), &self));
                }
                let mut bytes = [0u8; 64];
                bytes.copy_from_slice(value);
                Ok(Signature64(bytes))
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = [0u8; 64];
                for (index, byte) in bytes.iter_mut().enumerate() {
                    *byte = sequence
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(index, &self))?;
                }
                if sequence.next_element::<u8>()?.is_some() {
                    return Err(serde::de::Error::invalid_length(65, &self));
                }
                Ok(Signature64(bytes))
            }
        }
        deserializer.deserialize_bytes(Visitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SignedLimitOrder {
    pub order: LimitOrder,
    pub signature: Signature64,
}

impl SignedLimitOrder {
    pub fn sign(order: LimitOrder, secret_key: &SecretKey) -> Result<Self, ProtocolError> {
        order.validate()?;
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, secret_key);
        let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
        if xonly.serialize() != order.trader.0 {
            return Err(ProtocolError::SigningKeyMismatch);
        }
        let message = Message::from_digest_slice(&order.signing_digest())
            .map_err(|_| ProtocolError::InvalidSignature)?;
        let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);
        Ok(Self {
            order,
            signature: Signature64(*signature.as_ref()),
        })
    }

    pub fn verify(&self) -> Result<(), ProtocolError> {
        self.order.validate()?;
        let secp = Secp256k1::verification_only();
        let public_key = XOnlyPublicKey::from_slice(&self.order.trader.0)
            .map_err(|_| ProtocolError::InvalidSignature)?;
        let signature = schnorr::Signature::from_slice(&self.signature.0)
            .map_err(|_| ProtocolError::InvalidSignature)?;
        let message = Message::from_digest_slice(&self.order.signing_digest())
            .map_err(|_| ProtocolError::InvalidSignature)?;
        secp.verify_schnorr(&signature, &message, &public_key)
            .map_err(|_| ProtocolError::InvalidSignature)
    }

    pub fn order_id(&self) -> OrderId {
        self.order.order_id()
    }

    pub fn decode_fixed(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != SIGNED_ORDER_ENCODED_LEN {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        let order = LimitOrder::decode_fixed(&bytes[..LIMIT_ORDER_ENCODED_LEN])?;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[LIMIT_ORDER_ENCODED_LEN..]);
        Ok(Self {
            order,
            signature: Signature64(signature),
        })
    }
}

impl CanonicalEncode for SignedLimitOrder {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.order.encode_to(out);
        self.signature.encode_to(out);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CancelOrder {
    pub version: u8,
    pub chain_id: Hash32,
    pub market: MarketId,
    pub trader: XOnlyKey,
    pub order_id: OrderId,
    /// Fresh account nonce; cancellation consumes it exactly once.
    pub nonce: u64,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
}

impl CancelOrder {
    pub const VERSION: u8 = 1;

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

    pub fn is_live_at(&self, height: u64) -> bool {
        height >= self.valid_from_height && height <= self.expires_at_height
    }

    pub fn signing_digest(&self) -> Hash32 {
        canonical_hash("ECX/cancel-order/v1", self)
    }

    pub fn cancel_id(&self) -> Hash32 {
        canonical_hash("ECX/cancel-id/v1", self)
    }

    pub fn decode_fixed(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != CANCEL_ORDER_ENCODED_LEN {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        let mut decoder = Decoder::new(bytes);
        let cancel = Self {
            version: decoder.u8()?,
            chain_id: decoder.take()?,
            market: MarketId(decoder.take()?),
            trader: XOnlyKey(decoder.take()?),
            order_id: decoder.take()?,
            nonce: decoder.u64()?,
            valid_from_height: decoder.u64()?,
            expires_at_height: decoder.u64()?,
        };
        decoder.finish()?;
        cancel.validate()?;
        Ok(cancel)
    }
}

impl CanonicalEncode for CancelOrder {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.chain_id);
        self.market.encode_to(out);
        self.trader.encode_to(out);
        out.extend_from_slice(&self.order_id);
        put_u64(out, self.nonce);
        put_u64(out, self.valid_from_height);
        put_u64(out, self.expires_at_height);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SignedCancelOrder {
    pub cancel: CancelOrder,
    pub signature: Signature64,
}

impl SignedCancelOrder {
    pub fn sign(cancel: CancelOrder, secret_key: &SecretKey) -> Result<Self, ProtocolError> {
        cancel.validate()?;
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, secret_key);
        let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
        if xonly.serialize() != cancel.trader.0 {
            return Err(ProtocolError::SigningKeyMismatch);
        }
        let message = Message::from_digest_slice(&cancel.signing_digest())
            .map_err(|_| ProtocolError::InvalidSignature)?;
        let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);
        Ok(Self {
            cancel,
            signature: Signature64(*signature.as_ref()),
        })
    }

    pub fn verify(&self) -> Result<(), ProtocolError> {
        self.cancel.validate()?;
        let key = XOnlyPublicKey::from_slice(&self.cancel.trader.0)
            .map_err(|_| ProtocolError::InvalidSignature)?;
        let signature = schnorr::Signature::from_slice(&self.signature.0)
            .map_err(|_| ProtocolError::InvalidSignature)?;
        let message = Message::from_digest_slice(&self.cancel.signing_digest())
            .map_err(|_| ProtocolError::InvalidSignature)?;
        Secp256k1::verification_only()
            .verify_schnorr(&signature, &message, &key)
            .map_err(|_| ProtocolError::InvalidSignature)
    }

    pub fn decode_fixed(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != SIGNED_CANCEL_ENCODED_LEN {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        let cancel = CancelOrder::decode_fixed(&bytes[..CANCEL_ORDER_ENCODED_LEN])?;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[CANCEL_ORDER_ENCODED_LEN..]);
        Ok(Self {
            cancel,
            signature: Signature64(signature),
        })
    }
}

impl CanonicalEncode for SignedCancelOrder {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.cancel.encode_to(out);
        self.signature.encode_to(out);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TradeMatch {
    pub sequence: u64,
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

impl TradeMatch {
    pub fn validate_orders(
        &self,
        maker: &SignedLimitOrder,
        taker: &SignedLimitOrder,
        height: u64,
    ) -> Result<(), ProtocolError> {
        maker.verify()?;
        taker.verify()?;
        if !maker.order.is_live_at(height) || !taker.order.is_live_at(height) {
            return Err(ProtocolError::OrderNotLive);
        }
        if maker.order.market != ECX_USDD_MARKET
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
        canonical_hash("ECX/trade-match/v1", self)
    }
}

impl CanonicalEncode for TradeMatch {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u64(out, self.sequence);
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

/// Account-local projection of a [`TradeMatch`], convenient inside a proof guest.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Fill {
    pub match_id: Hash32,
    pub trader: XOnlyKey,
    pub side: Side,
    pub price: Price,
    pub quantity: Quantity,
    pub fee: Amount,
}

impl TradeMatch {
    pub fn maker_fill(&self) -> Fill {
        Fill {
            match_id: self.match_id(),
            trader: self.maker,
            side: self.maker_side,
            price: self.price,
            quantity: self.quantity,
            fee: self.maker_fee,
        }
    }

    pub fn taker_fill(&self) -> Fill {
        Fill {
            match_id: self.match_id(),
            trader: self.taker,
            side: self.maker_side.opposite(),
            price: self.price,
            quantity: self.quantity,
            fee: self.taker_fee,
        }
    }
}

impl CanonicalEncode for Fill {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.match_id);
        self.trader.encode_to(out);
        put_u8(out, self.side as u8);
        self.price.encode_to(out);
        self.quantity.encode_to(out);
        self.fee.encode_to(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PRICE_SCALE;

    fn signed(side: Side, price: u64, nonce: u64) -> SignedLimitOrder {
        let secret = SecretKey::from_slice(&[nonce as u8 + 1; 32]).unwrap();
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (key, _) = XOnlyPublicKey::from_keypair(&keypair);
        SignedLimitOrder::sign(
            LimitOrder {
                version: 1,
                chain_id: [7; 32],
                market: ECX_USDD_MARKET,
                trader: XOnlyKey(key.serialize()),
                side,
                time_in_force: TimeInForce::GoodTilHeight,
                flags: OrderFlags::NONE,
                limit_price: Price::new(price).unwrap(),
                quantity: Quantity::new(10).unwrap(),
                client_order_id: [nonce as u8; 16],
                max_fee_bps: 20,
                nonce,
                valid_from_height: 100,
                expires_at_height: 200,
            },
            &secret,
        )
        .unwrap()
    }

    #[test]
    fn order_encoding_is_fixed_and_roundtrips() {
        let signed = signed(Side::Buy, PRICE_SCALE, 1);
        let bytes = signed.canonical_bytes();
        assert_eq!(bytes.len(), SIGNED_ORDER_ENCODED_LEN);
        assert_eq!(SignedLimitOrder::decode_fixed(&bytes).unwrap(), signed);
    }

    #[test]
    fn bip340_signature_binds_every_replay_field() {
        let signed = signed(Side::Buy, PRICE_SCALE, 1);
        signed.verify().unwrap();

        let mut changed = signed.clone();
        changed.order.chain_id[0] ^= 1;
        assert_eq!(changed.verify(), Err(ProtocolError::InvalidSignature));

        let mut changed = signed.clone();
        changed.order.nonce += 1;
        assert_eq!(changed.verify(), Err(ProtocolError::InvalidSignature));

        let mut changed = signed.clone();
        changed.order.expires_at_height += 1;
        assert_eq!(changed.verify(), Err(ProtocolError::InvalidSignature));
    }

    #[test]
    fn match_enforces_cross_and_maker_price() {
        let maker = signed(Side::Sell, 110 * PRICE_SCALE, 1);
        let taker = signed(Side::Buy, 111 * PRICE_SCALE, 2);
        let trade = TradeMatch {
            sequence: 1,
            maker_order_id: maker.order_id(),
            taker_order_id: taker.order_id(),
            maker: maker.order.trader,
            taker: taker.order.trader,
            maker_side: Side::Sell,
            price: maker.order.limit_price,
            quantity: Quantity::new(4).unwrap(),
            maker_fee: Amount(0),
            taker_fee: Amount(1),
        };
        trade.validate_orders(&maker, &taker, 150).unwrap();

        let mut bad = trade;
        bad.price = Price::new(109 * PRICE_SCALE).unwrap();
        assert_eq!(
            bad.validate_orders(&maker, &taker, 150),
            Err(ProtocolError::IncompatibleOrders)
        );
    }

    #[test]
    fn serde_rejects_wrong_length_signature() {
        let value = serde_json::json!({
            "order": signed(Side::Buy, PRICE_SCALE, 1).order,
            "signature": [0, 1, 2]
        });
        assert!(serde_json::from_value::<SignedLimitOrder>(value).is_err());
    }

    #[test]
    fn signed_cancel_binds_order_owner_nonce_and_chain() {
        let order = signed(Side::Buy, PRICE_SCALE, 3);
        let secret = SecretKey::from_slice(&[4; 32]).unwrap();
        let cancel = SignedCancelOrder::sign(
            CancelOrder {
                version: 1,
                chain_id: order.order.chain_id,
                market: order.order.market,
                trader: order.order.trader,
                order_id: order.order_id(),
                nonce: 4,
                valid_from_height: 120,
                expires_at_height: 180,
            },
            &secret,
        )
        .unwrap();
        cancel.verify().unwrap();
        let encoded = cancel.canonical_bytes();
        assert_eq!(encoded.len(), SIGNED_CANCEL_ENCODED_LEN);
        assert_eq!(SignedCancelOrder::decode_fixed(&encoded).unwrap(), cancel);

        let mut replay = cancel;
        replay.cancel.chain_id[0] ^= 1;
        assert_eq!(replay.verify(), Err(ProtocolError::InvalidSignature));
    }
}
