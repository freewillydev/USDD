use crate::codec::{put_i128, put_i64, put_u64, CanonicalEncode};
use crate::ProtocolError;

/// Prices use eight decimal places: 1 USDD = 100_000_000 price units.
pub const PRICE_SCALE: u64 = 100_000_000;

/// The canonical 16-byte market identifier, padded with zero bytes.
pub const ECX_USDD_MARKET: MarketId = MarketId(*b"ECX-USDD-PERP\0\0\0");

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MarketId(pub [u8; 16]);

impl MarketId {
    pub fn validate(self) -> Result<Self, ProtocolError> {
        if self == ECX_USDD_MARKET {
            Ok(self)
        } else {
            Err(ProtocolError::InvalidMarket)
        }
    }
}

impl CanonicalEncode for MarketId {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct XOnlyKey(pub [u8; 32]);

impl CanonicalEncode for XOnlyKey {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Price(u64);

impl Price {
    pub fn new(value: u64) -> Result<Self, ProtocolError> {
        if value == 0 {
            Err(ProtocolError::InvalidPrice)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl CanonicalEncode for Price {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u64(out, self.0);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Quantity(u64);

impl Quantity {
    pub fn new(value: u64) -> Result<Self, ProtocolError> {
        if value == 0 || value > i64::MAX as u64 {
            Err(ProtocolError::InvalidQuantity)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl CanonicalEncode for Quantity {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u64(out, self.0);
    }
}

/// Signed USDD atomic units. Negative values are valid inside state transitions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Amount(pub i128);

impl Amount {
    pub fn checked_add(self, rhs: Self) -> Result<Self, ProtocolError> {
        self.0
            .checked_add(rhs.0)
            .map(Self)
            .ok_or(ProtocolError::ArithmeticOverflow)
    }

    pub fn checked_sub(self, rhs: Self) -> Result<Self, ProtocolError> {
        self.0
            .checked_sub(rhs.0)
            .map(Self)
            .ok_or(ProtocolError::ArithmeticOverflow)
    }
}

impl CanonicalEncode for Amount {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_i128(out, self.0);
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Position {
    /// Signed ECX base units. Positive is long; negative is short.
    pub size: i64,
    /// Weighted entry price, or zero iff `size == 0`.
    pub entry_price: u64,
    /// Cumulative funding index already settled into collateral.
    pub last_funding_index: i128,
}

impl Position {
    pub const FLAT: Self = Self {
        size: 0,
        entry_price: 0,
        last_funding_index: 0,
    };

    pub fn validate(self) -> Result<Self, ProtocolError> {
        if (self.size == 0) == (self.entry_price == 0) {
            Ok(self)
        } else {
            Err(ProtocolError::NonCanonicalEncoding)
        }
    }
}

impl CanonicalEncode for Position {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_i64(out, self.size);
        put_u64(out, self.entry_price);
        put_i128(out, self.last_funding_index);
    }
}
