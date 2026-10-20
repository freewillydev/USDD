//! Additive primitives for the bounded incremental successor relation.
//!
//! This module deliberately does not replace [`crate::TransitionWitnessV2`]
//! or change the current V2 program identity.  It defines the authenticated
//! state and exact-accounting building blocks required by the successor proof
//! described in `docs/INCREMENTAL_STATE_V2.md`.
//!
//! Sparse paths are fixed at 256 levels.  Sibling zero is adjacent to the
//! leaf, and level `n` selects bit `n` of the key, where bit zero is the least
//! significant bit of `key[31]`.  Empty leaves and every parent height are
//! domain separated.  Parent hashes commit both child hashes, both child sums,
//! and the checked combined sum, so a hash cannot be reused with a different
//! aggregate preimage.

use std::collections::BTreeSet;

use crypto_bigint::{CheckedAdd, CheckedMul, CheckedSub, Encoding, NonZero, Zero, U256};
use secp256k1::XOnlyPublicKey;

use crate::codec::{put_i128, put_u16, put_u32, put_u64, put_u8, CanonicalEncode};
use crate::hash::{canonical_hash, tagged_hash, Hash32};
use crate::order::{OrderId, Side, TimeInForce};
use crate::risk::RiskParams;
use crate::risk_v2::{OrderRiskCommitmentV2, ALLOWED_INITIAL_MARGIN_BPS_V2};
use crate::successor_action_v2::SuccessorSignedLimitOrderV2;
use crate::types::{MarketId, XOnlyKey, PRICE_SCALE};
use crate::ProtocolError;

pub const SPARSE_MERKLE_SUM_DEPTH_V2: usize = 256;
pub const MAX_SPARSE_MERKLE_SUM_UPDATES_PER_BATCH_V2: usize = 64;
/// Isolated budget for one maximum shared-frontier sparse-update class.  This
/// admits the proven 5,872,645-byte worst case with 64 updated keys and all
/// 16,000 disjoint frontier subtrees occupied.  The future successor witness
/// must still allocate every other proof class inside the global 16 MiB
/// recovery budget; this isolated 6 MiB cap does not relax that global limit.
pub const MAX_SPARSE_MERKLE_SUM_UPDATE_BATCH_BYTES_V2: usize = 6 * 1024 * 1024;
/// The chained full-path API is a fail-closed reference implementation, not the
/// successor witness. Keep its earlier isolated cap so callers cannot silently
/// substitute 64 repeated 256-node paths for the shared-frontier proof.
pub const MAX_CHAINED_SPARSE_MERKLE_SUM_UPDATE_BATCH_BYTES_V2: usize = 3 * 1024 * 1024;
pub const MAX_SPARSE_NULLIFIER_UPDATE_BATCH_BYTES_V2: usize = 1024 * 1024;
pub const DEFICIT_INDEX_KEY_BYTES_V2: usize = 65;
pub const DEFICIT_INDEX_DEPTH_V2: usize = DEFICIT_INDEX_KEY_BYTES_V2 * 8;
/// One root-to-leaf ordered range proof has 520 canonical path items. Even an
/// all-occupied path remains below this isolated cap; this does not prove the
/// all-class successor witness bound.
pub const MAX_DEFICIT_INDEX_RANGE_PROOF_BYTES_V2: usize = 64 * 1024;
/// One typed insert/remove proof opens the trader leaf and carries the same
/// 520-level ordered path as a range proof.  Keep its budget distinct even
/// though both current wire maxima fit inside 64 KiB.
pub const MAX_DEFICIT_INDEX_UPDATE_BYTES_V2: usize = 64 * 1024;
pub const MAX_DEFICIT_INDEX_UPDATES_PER_BATCH_V2: usize =
    2 * MAX_SPARSE_MERKLE_SUM_UPDATES_PER_BATCH_V2;
/// With 128 distinct ordered keys in a 520-level binary trie, the maximum
/// deterministic omitted-subtree frontier is `128 * (520 - log2(128))`.
pub const MAX_DEFICIT_INDEX_SHARED_FRONTIER_ITEMS_V2: usize = 65_664;
/// Exact universal maximum wire shape is 6,458,504 bytes: 128 fixed-width
/// typed mutations plus 65,664 occupied 98-byte frontier nodes and headers.
pub const MAX_SHARED_DEFICIT_INDEX_UPDATE_BATCH_BYTES_V2: usize = 7 * 1024 * 1024;
/// Fail-closed reference budget for 128 full 520-level typed paths. A future
/// successor must replace this with a shared frontier before the global gate
/// can become true.
pub const MAX_CHAINED_DEFICIT_INDEX_UPDATE_BATCH_BYTES_V2: usize = 8 * 1024 * 1024;
/// At most 64 accepted order operations are replayed in one successor batch.
/// Multiple operations on one order id are coalesced to one sparse-tree leaf
/// replacement after their exact logical chain is checked.
pub const MAX_ORDER_INDEX_OPERATIONS_PER_BATCH_V2: usize = 64;
pub const MAX_ORDER_INDEX_UNIQUE_KEYS_PER_BATCH_V2: usize = 64;
/// A 256-level binary trie with 64 distinct updated keys has at most
/// `64 * (256 - log2(64)) = 16_000` omitted sibling subtrees.
pub const MAX_ORDER_INDEX_SHARED_FRONTIER_ITEMS_V2: usize = 16_000;
/// Isolated universal wire cap for the typed order-index shared frontier. The
/// exact closed-form maximum is asserted by a regression test below. This cap
/// does not make the all-class 16 MiB successor gate true.
pub const MAX_ORDER_INDEX_UPDATE_BATCH_BYTES_V2: usize = 4 * 1024 * 1024;
pub const MAX_CHAINED_ORDER_INDEX_TRANSCRIPT_BYTES_V2: usize = 4 * 1024 * 1024;
/// Explicit release-gate signal. All twelve recursive child classes have
/// enforced isolated maxima and the compact outer descriptor record is bounded,
/// but production completeness still lacks a frozen pristine activation and
/// the simultaneous all-class reachability theorem. Node patch 0009 mirrors
/// the proof-enforced forced-tranche admission budget, but is not activated.
pub const INCREMENTAL_SUCCESSOR_GLOBAL_WITNESS_BOUND_PROVEN_V2: bool = false;
const _: () = assert!(!INCREMENTAL_SUCCESSOR_GLOBAL_WITNESS_BOUND_PROVEN_V2);

const SPARSE_MERKLE_SUM_VERSION_V2: u8 = 1;
pub const FUNDING_INDEX_DENOMINATOR_V2: u64 = 1_000_000;
pub const EXACT_ACCOUNTING_DENOMINATOR_V2: u64 = PRICE_SCALE * FUNDING_INDEX_DENOMINATOR_V2;
pub const MAX_ABS_FUNDING_RATE_PPM_V2: i32 = 10_000;
/// Maximum new leaves/nullifiers reachable with 64 insertions in every block
/// of the complete `u64` sidechain-height namespace.
pub const MAX_REACHABLE_INCREMENTAL_LEAF_COUNT_V2: u128 =
    (u64::MAX as u128 + 1) * MAX_SPARSE_MERKLE_SUM_UPDATES_PER_BATCH_V2 as u128;
const SIGNED_256_MAX_MAGNITUDE_V2: U256 =
    U256::from_be_hex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

/// Reviewable fixed-width magnitude used where lifetime funding or exact cost
/// products can exceed `i128`. Arithmetic delegates to pinned
/// `crypto-bigint` 0.5.5; consensus encoding is one fixed 32-byte big-endian
/// magnitude and does not depend on its host limb representation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Uint256V2(U256);

impl Uint256V2 {
    pub const ZERO: Self = Self(U256::ZERO);

    pub const fn from_u64(value: u64) -> Self {
        Self(U256::from_u64(value))
    }

    pub const fn from_u128(value: u128) -> Self {
        Self(U256::from_u128(value))
    }

    pub fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self(U256::from_be_bytes(bytes))
    }

    pub fn is_zero(self) -> bool {
        bool::from(self.0.is_zero())
    }

    pub fn checked_add(self, rhs: Self) -> Result<Self, ProtocolError> {
        Option::<U256>::from(self.0.checked_add(&rhs.0))
            .map(Self)
            .ok_or(ProtocolError::ArithmeticOverflow)
    }

    pub fn checked_sub(self, rhs: Self) -> Result<Self, ProtocolError> {
        Option::<U256>::from(self.0.checked_sub(&rhs.0))
            .map(Self)
            .ok_or(ProtocolError::ArithmeticOverflow)
    }

    pub fn checked_mul_u64(self, rhs: u64) -> Result<Self, ProtocolError> {
        Option::<U256>::from(self.0.checked_mul(&U256::from_u64(rhs)))
            .map(Self)
            .ok_or(ProtocolError::ArithmeticOverflow)
    }

    pub fn checked_mul_u128(self, rhs: u128) -> Result<Self, ProtocolError> {
        Option::<U256>::from(self.0.checked_mul(&U256::from_u128(rhs)))
            .map(Self)
            .ok_or(ProtocolError::ArithmeticOverflow)
    }

    pub fn div_rem_u64(self, divisor: u64) -> Result<(Self, u64), ProtocolError> {
        let divisor = NonZero::new(U256::from_u64(divisor));
        let divisor =
            Option::<NonZero<U256>>::from(divisor).ok_or(ProtocolError::DivisionByZero)?;
        let (quotient, remainder) = self.0.div_rem(&divisor);
        let remainder_bytes = remainder.to_be_bytes();
        if remainder_bytes[..24].iter().any(|byte| *byte != 0) {
            return Err(ProtocolError::ArithmeticOverflow);
        }
        Ok((
            Self(quotient),
            u64::from_be_bytes(
                remainder_bytes[24..]
                    .try_into()
                    .map_err(|_| ProtocolError::ArithmeticOverflow)?,
            ),
        ))
    }

    pub fn try_to_u128(self) -> Result<u128, ProtocolError> {
        let bytes = self.0.to_be_bytes();
        if bytes[..16].iter().any(|byte| *byte != 0) {
            return Err(ProtocolError::ArithmeticOverflow);
        }
        Ok(u128::from_be_bytes(
            bytes[16..]
                .try_into()
                .map_err(|_| ProtocolError::ArithmeticOverflow)?,
        ))
    }

    pub fn to_be_bytes(self) -> [u8; 32] {
        self.0.to_be_bytes()
    }
}

impl CanonicalEncode for Uint256V2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_be_bytes());
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Uint256V2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde::Serialize::serialize(&self.to_be_bytes(), serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Uint256V2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <[u8; 32] as serde::Deserialize>::deserialize(deserializer)?;
        Ok(Self::from_be_bytes(bytes))
    }
}

/// Canonical 33-byte signed-magnitude integer in the symmetric range
/// `[-(2^255 - 1), 2^255 - 1]`. Negative zero and both `+/-2^255` are
/// rejected, giving every accepted value one encoding.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Int256V2 {
    negative: bool,
    magnitude: Uint256V2,
}

impl Int256V2 {
    pub const ZERO: Self = Self {
        negative: false,
        magnitude: Uint256V2::ZERO,
    };

    pub fn from_i128(value: i128) -> Self {
        Self {
            negative: value < 0,
            magnitude: Uint256V2::from_u128(value.unsigned_abs()),
        }
        .normalized()
    }

    pub fn from_u128(value: u128) -> Self {
        Self {
            negative: false,
            magnitude: Uint256V2::from_u128(value),
        }
    }

    pub fn from_sign_and_magnitude(
        negative: bool,
        magnitude_be: [u8; 32],
    ) -> Result<Self, ProtocolError> {
        Self {
            negative,
            magnitude: Uint256V2::from_be_bytes(magnitude_be),
        }
        .validate()
        .map(|()| Self {
            negative,
            magnitude: Uint256V2::from_be_bytes(magnitude_be),
        })
    }

    pub const fn is_negative(self) -> bool {
        self.negative
    }

    pub const fn magnitude(self) -> Uint256V2 {
        self.magnitude
    }

    fn normalized(mut self) -> Self {
        if self.magnitude.is_zero() {
            self.negative = false;
        }
        self
    }

    fn checked_result(self) -> Result<Self, ProtocolError> {
        let value = self.normalized();
        if value.magnitude.0 > SIGNED_256_MAX_MAGNITUDE_V2 {
            Err(ProtocolError::ArithmeticOverflow)
        } else {
            Ok(value)
        }
    }

    pub fn validate(self) -> Result<(), ProtocolError> {
        if (self.negative && self.magnitude.is_zero())
            || self.magnitude.0 > SIGNED_256_MAX_MAGNITUDE_V2
        {
            Err(ProtocolError::NonCanonicalEncoding)
        } else {
            Ok(())
        }
    }

    pub fn checked_neg(self) -> Result<Self, ProtocolError> {
        self.validate()?;
        Ok(if self.magnitude.is_zero() {
            Self::ZERO
        } else {
            Self {
                negative: !self.negative,
                magnitude: self.magnitude,
            }
        })
    }

    pub fn checked_add(self, rhs: Self) -> Result<Self, ProtocolError> {
        self.validate()?;
        rhs.validate()?;
        let value = if self.negative == rhs.negative {
            Self {
                negative: self.negative,
                magnitude: self.magnitude.checked_add(rhs.magnitude)?,
            }
        } else if self.magnitude >= rhs.magnitude {
            Self {
                negative: self.negative,
                magnitude: self.magnitude.checked_sub(rhs.magnitude)?,
            }
        } else {
            Self {
                negative: rhs.negative,
                magnitude: rhs.magnitude.checked_sub(self.magnitude)?,
            }
        };
        value.checked_result()
    }

    pub fn checked_sub(self, rhs: Self) -> Result<Self, ProtocolError> {
        self.checked_add(rhs.checked_neg()?)
    }

    pub fn checked_mul_u64(self, rhs: u64) -> Result<Self, ProtocolError> {
        self.validate()?;
        Self {
            negative: self.negative,
            magnitude: self.magnitude.checked_mul_u64(rhs)?,
        }
        .checked_result()
    }

    pub fn checked_mul_u128(self, rhs: u128) -> Result<Self, ProtocolError> {
        self.validate()?;
        Self {
            negative: self.negative,
            magnitude: self.magnitude.checked_mul_u128(rhs)?,
        }
        .checked_result()
    }

    pub fn checked_mul_i128(self, rhs: i128) -> Result<Self, ProtocolError> {
        self.validate()?;
        Self {
            negative: self.negative ^ (rhs < 0),
            magnitude: self.magnitude.checked_mul_u128(rhs.unsigned_abs())?,
        }
        .checked_result()
    }

    pub fn checked_product_i64_i128(lhs: i64, rhs: i128) -> Result<Self, ProtocolError> {
        let magnitude =
            Uint256V2::from_u128(rhs.unsigned_abs()).checked_mul_u64(lhs.unsigned_abs())?;
        Self {
            negative: (lhs < 0) ^ (rhs < 0),
            magnitude,
        }
        .checked_result()
    }

    pub fn div_rem_u64_toward_zero(self, divisor: u64) -> Result<(Self, i128), ProtocolError> {
        self.validate()?;
        let (magnitude, remainder) = self.magnitude.div_rem_u64(divisor)?;
        let signed_remainder = i128::from(remainder);
        Ok((
            Self {
                negative: self.negative,
                magnitude,
            }
            .normalized(),
            if self.negative {
                -signed_remainder
            } else {
                signed_remainder
            },
        ))
    }

    /// Mathematical floor division by a positive divisor.
    pub fn floor_div_u64(self, divisor: u64) -> Result<Self, ProtocolError> {
        let (quotient, remainder) = self.div_rem_u64_toward_zero(divisor)?;
        if remainder < 0 {
            quotient.checked_sub(Self::from_i128(1))
        } else {
            Ok(quotient)
        }
    }

    /// Mathematical ceiling division by a positive divisor.
    pub fn ceil_div_u64(self, divisor: u64) -> Result<Self, ProtocolError> {
        let (quotient, remainder) = self.div_rem_u64_toward_zero(divisor)?;
        if remainder > 0 {
            quotient.checked_add(Self::from_i128(1))
        } else {
            Ok(quotient)
        }
    }

    pub fn try_to_i128(self) -> Result<i128, ProtocolError> {
        self.validate()?;
        let magnitude = self.magnitude.try_to_u128()?;
        if self.negative {
            if magnitude == (1u128 << 127) {
                Ok(i128::MIN)
            } else {
                i128::try_from(magnitude)
                    .map(i128::saturating_neg)
                    .map_err(|_| ProtocolError::ArithmeticOverflow)
            }
        } else {
            i128::try_from(magnitude).map_err(|_| ProtocolError::ArithmeticOverflow)
        }
    }
}

impl Ord for Int256V2 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self.negative, other.negative) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            (true, true) => other.magnitude.cmp(&self.magnitude),
            (false, false) => self.magnitude.cmp(&other.magnitude),
        }
    }
}

impl PartialOrd for Int256V2 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl CanonicalEncode for Int256V2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, u8::from(self.negative));
        self.magnitude.encode_to(out);
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Int256V2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeTuple;

        self.validate().map_err(serde::ser::Error::custom)?;
        let mut tuple = serializer.serialize_tuple(2)?;
        tuple.serialize_element(&u8::from(self.negative))?;
        tuple.serialize_element(&self.magnitude.to_be_bytes())?;
        tuple.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Int256V2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (sign, magnitude) = <(u8, [u8; 32]) as serde::Deserialize>::deserialize(deserializer)?;
        if sign > 1 {
            return Err(serde::de::Error::custom("invalid signed-256 sign byte"));
        }
        Self::from_sign_and_magnitude(sign == 1, magnitude).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SparseStateDomainV2 {
    Trader,
    DepositNullifier,
    WithdrawalNullifier,
    LongDeficit,
    ShortDeficit,
    RiskExtrema,
}

impl SparseStateDomainV2 {
    pub const fn code(self) -> u8 {
        match self {
            Self::Trader => 1,
            Self::DepositNullifier => 2,
            Self::WithdrawalNullifier => 3,
            Self::LongDeficit => 4,
            Self::ShortDeficit => 5,
            Self::RiskExtrema => 6,
        }
    }
}

impl CanonicalEncode for SparseStateDomainV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.code());
    }
}

/// Additive root preimage used by the trader tree and sparse-set trees.
///
/// Lifetime cost and funding products use signed 256-bit values. Gross fields
/// make each signed sum independently auditable even when opposing traders
/// cancel at the root.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TraderAggregateV2 {
    pub leaf_count: u128,
    pub total_collateral_atoms: i128,
    /// Sum of absolute per-trader integer collateral.  This prevents signed
    /// cancellation from bypassing the authenticated supply bound.
    pub gross_collateral_atoms: u128,
    pub net_position_atoms: i128,
    pub long_open_interest_atoms: u128,
    pub short_open_interest_atoms: u128,
    pub signed_cost_basis_numerator: Int256V2,
    pub gross_cost_basis_numerator: Uint256V2,
    pub fractional_cash_numerator: Int256V2,
    pub gross_fractional_cash_numerator: Uint256V2,
    /// Sum of the exact negative-cash magnitudes of flat traders. The finite
    /// V2 relation can close a position to flat while leaving bad debt, so a
    /// successor must authenticate this amount rather than silently omit or
    /// reject a reachable state.
    pub flat_negative_exact_cash_numerator: Uint256V2,
    /// Sum of `position_size * last_funding_index`.  Together with the global
    /// index and net size, this prices all still-lazy funding exactly.
    pub lazy_funding_checkpoint_numerator: Int256V2,
    pub gross_lazy_funding_checkpoint_numerator: Uint256V2,
    /// Carried extrema for the position-risk selection committed in every
    /// trader leaf. Zero is reserved for the canonical empty aggregate.
    pub minimum_selected_initial_margin_bps: u32,
    pub maximum_selected_initial_margin_bps: u32,
}

impl TraderAggregateV2 {
    pub const ZERO: Self = Self {
        leaf_count: 0,
        total_collateral_atoms: 0,
        gross_collateral_atoms: 0,
        net_position_atoms: 0,
        long_open_interest_atoms: 0,
        short_open_interest_atoms: 0,
        signed_cost_basis_numerator: Int256V2::ZERO,
        gross_cost_basis_numerator: Uint256V2::ZERO,
        fractional_cash_numerator: Int256V2::ZERO,
        gross_fractional_cash_numerator: Uint256V2::ZERO,
        flat_negative_exact_cash_numerator: Uint256V2::ZERO,
        lazy_funding_checkpoint_numerator: Int256V2::ZERO,
        gross_lazy_funding_checkpoint_numerator: Uint256V2::ZERO,
        minimum_selected_initial_margin_bps: 0,
        maximum_selected_initial_margin_bps: 0,
    };

    pub fn checked_add(self, rhs: Self) -> Result<Self, ProtocolError> {
        Ok(Self {
            leaf_count: self
                .leaf_count
                .checked_add(rhs.leaf_count)
                .ok_or(ProtocolError::ArithmeticOverflow)?,
            total_collateral_atoms: self
                .total_collateral_atoms
                .checked_add(rhs.total_collateral_atoms)
                .ok_or(ProtocolError::ArithmeticOverflow)?,
            gross_collateral_atoms: self
                .gross_collateral_atoms
                .checked_add(rhs.gross_collateral_atoms)
                .ok_or(ProtocolError::ArithmeticOverflow)?,
            net_position_atoms: self
                .net_position_atoms
                .checked_add(rhs.net_position_atoms)
                .ok_or(ProtocolError::ArithmeticOverflow)?,
            long_open_interest_atoms: self
                .long_open_interest_atoms
                .checked_add(rhs.long_open_interest_atoms)
                .ok_or(ProtocolError::ArithmeticOverflow)?,
            short_open_interest_atoms: self
                .short_open_interest_atoms
                .checked_add(rhs.short_open_interest_atoms)
                .ok_or(ProtocolError::ArithmeticOverflow)?,
            signed_cost_basis_numerator: self
                .signed_cost_basis_numerator
                .checked_add(rhs.signed_cost_basis_numerator)?,
            gross_cost_basis_numerator: self
                .gross_cost_basis_numerator
                .checked_add(rhs.gross_cost_basis_numerator)?,
            fractional_cash_numerator: self
                .fractional_cash_numerator
                .checked_add(rhs.fractional_cash_numerator)?,
            gross_fractional_cash_numerator: self
                .gross_fractional_cash_numerator
                .checked_add(rhs.gross_fractional_cash_numerator)?,
            flat_negative_exact_cash_numerator: self
                .flat_negative_exact_cash_numerator
                .checked_add(rhs.flat_negative_exact_cash_numerator)?,
            lazy_funding_checkpoint_numerator: self
                .lazy_funding_checkpoint_numerator
                .checked_add(rhs.lazy_funding_checkpoint_numerator)?,
            gross_lazy_funding_checkpoint_numerator: self
                .gross_lazy_funding_checkpoint_numerator
                .checked_add(
                rhs.gross_lazy_funding_checkpoint_numerator,
            )?,
            minimum_selected_initial_margin_bps: match (
                self.minimum_selected_initial_margin_bps,
                rhs.minimum_selected_initial_margin_bps,
            ) {
                (0, value) | (value, 0) => value,
                (left, right) => left.min(right),
            },
            maximum_selected_initial_margin_bps: self
                .maximum_selected_initial_margin_bps
                .max(rhs.maximum_selected_initial_margin_bps),
        })
    }

    pub fn is_zero(self) -> bool {
        self == Self::ZERO
    }

    pub fn validate(self, bounds: IncrementalAccountingBoundsV2) -> Result<(), ProtocolError> {
        bounds.validate()?;
        if self.leaf_count == 0 {
            return if self.is_zero() {
                Ok(())
            } else {
                Err(ProtocolError::InvalidBondState)
            };
        }

        let long = i128::try_from(self.long_open_interest_atoms)
            .map_err(|_| ProtocolError::ArithmeticOverflow)?;
        let short = i128::try_from(self.short_open_interest_atoms)
            .map_err(|_| ProtocolError::ArithmeticOverflow)?;
        let expected_net = long
            .checked_sub(short)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        let gross_position_atoms = self
            .long_open_interest_atoms
            .checked_add(self.short_open_interest_atoms)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        let maximum_gross_cost = Uint256V2::from_u128(gross_position_atoms)
            .checked_mul_u64(bounds.maximum_price_atoms)?
            .checked_mul_u64(FUNDING_INDEX_DENOMINATOR_V2)?;
        if self.leaf_count > MAX_REACHABLE_INCREMENTAL_LEAF_COUNT_V2 {
            return Err(ProtocolError::InvalidBondState);
        }
        let maximum_fractional = Uint256V2::from_u128(self.leaf_count)
            .checked_mul_u64(EXACT_ACCOUNTING_DENOMINATOR_V2 - 1)?;
        let maximum_lazy_funding = Uint256V2::from_u128(gross_position_atoms)
            .checked_mul_u128(maximum_reachable_abs_funding_index_v2()?.unsigned_abs())?;
        let maximum_gross_exact_cash = Uint256V2::from_u128(self.gross_collateral_atoms)
            .checked_mul_u64(EXACT_ACCOUNTING_DENOMINATOR_V2)?
            .checked_add(self.gross_fractional_cash_numerator)?;

        self.signed_cost_basis_numerator.validate()?;
        self.fractional_cash_numerator.validate()?;
        self.lazy_funding_checkpoint_numerator.validate()?;

        if self.total_collateral_atoms.unsigned_abs() > self.gross_collateral_atoms
            || self.gross_collateral_atoms > bounds.maximum_reachable_gross_trader_cash_atoms()?
            || self.long_open_interest_atoms > bounds.maximum_open_interest_atoms
            || self.short_open_interest_atoms > bounds.maximum_open_interest_atoms
            || self.net_position_atoms != expected_net
            || self.gross_cost_basis_numerator > maximum_gross_cost
            || self.signed_cost_basis_numerator.magnitude > self.gross_cost_basis_numerator
            || self.gross_fractional_cash_numerator > maximum_fractional
            || self.fractional_cash_numerator.magnitude > self.gross_fractional_cash_numerator
            || self.flat_negative_exact_cash_numerator > maximum_gross_exact_cash
            || self.gross_lazy_funding_checkpoint_numerator > maximum_lazy_funding
            || self.lazy_funding_checkpoint_numerator.magnitude
                > self.gross_lazy_funding_checkpoint_numerator
            || !ALLOWED_INITIAL_MARGIN_BPS_V2.contains(&self.minimum_selected_initial_margin_bps)
            || !ALLOWED_INITIAL_MARGIN_BPS_V2.contains(&self.maximum_selected_initial_margin_bps)
            || self.minimum_selected_initial_margin_bps > self.maximum_selected_initial_margin_bps
        {
            return Err(ProtocolError::InvalidBondState);
        }
        Ok(())
    }
}

impl CanonicalEncode for TraderAggregateV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.leaf_count.to_be_bytes());
        put_i128(out, self.total_collateral_atoms);
        out.extend_from_slice(&self.gross_collateral_atoms.to_be_bytes());
        put_i128(out, self.net_position_atoms);
        out.extend_from_slice(&self.long_open_interest_atoms.to_be_bytes());
        out.extend_from_slice(&self.short_open_interest_atoms.to_be_bytes());
        self.signed_cost_basis_numerator.encode_to(out);
        self.gross_cost_basis_numerator.encode_to(out);
        self.fractional_cash_numerator.encode_to(out);
        self.gross_fractional_cash_numerator.encode_to(out);
        self.flat_negative_exact_cash_numerator.encode_to(out);
        self.lazy_funding_checkpoint_numerator.encode_to(out);
        self.gross_lazy_funding_checkpoint_numerator.encode_to(out);
        put_u32(out, self.minimum_selected_initial_margin_bps);
        put_u32(out, self.maximum_selected_initial_margin_bps);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SparseMerkleSumNodeV2 {
    pub hash: Hash32,
    pub aggregate: TraderAggregateV2,
}

impl CanonicalEncode for SparseMerkleSumNodeV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.hash);
        self.aggregate.encode_to(out);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SparseMerkleSumRootV2 {
    pub domain: SparseStateDomainV2,
    pub hash: Hash32,
    pub aggregate: TraderAggregateV2,
}

impl SparseMerkleSumRootV2 {
    pub(crate) fn from_node(domain: SparseStateDomainV2, node: SparseMerkleSumNodeV2) -> Self {
        Self {
            domain,
            hash: node.hash,
            aggregate: node.aggregate,
        }
    }
}

impl CanonicalEncode for SparseMerkleSumRootV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.domain.encode_to(out);
        out.extend_from_slice(&self.hash);
        self.aggregate.encode_to(out);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SparseMerkleSumLeafV2 {
    pub present: bool,
    pub value_commitment: Hash32,
    pub aggregate: TraderAggregateV2,
}

impl SparseMerkleSumLeafV2 {
    pub const EMPTY: Self = Self {
        present: false,
        value_commitment: [0; 32],
        aggregate: TraderAggregateV2::ZERO,
    };

    pub fn present(
        value_commitment: Hash32,
        aggregate: TraderAggregateV2,
    ) -> Result<Self, ProtocolError> {
        let leaf = Self {
            present: true,
            value_commitment,
            aggregate,
        };
        leaf.validate()?;
        Ok(leaf)
    }

    fn validate(self) -> Result<(), ProtocolError> {
        if self.present {
            if self.value_commitment == [0; 32] || self.aggregate.leaf_count != 1 {
                return Err(ProtocolError::InvalidMerkleProof);
            }
        } else if self.value_commitment != [0; 32] || !self.aggregate.is_zero() {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        Ok(())
    }
}

impl CanonicalEncode for SparseMerkleSumLeafV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, u8::from(self.present));
        out.extend_from_slice(&self.value_commitment);
        self.aggregate.encode_to(out);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SparseMerkleSumPathV2 {
    pub domain: SparseStateDomainV2,
    /// Bottom-up siblings.  This vector must contain exactly 256 entries.
    pub siblings: Vec<SparseMerkleSumNodeV2>,
}

impl CanonicalEncode for SparseMerkleSumPathV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.domain.encode_to(out);
        // Verifiers reject every length other than the frozen depth before
        // encoding. Saturating the diagnostic encoding avoids a process panic
        // if an untrusted deserialized value is encoded directly.
        put_u16(out, u16::try_from(self.siblings.len()).unwrap_or(u16::MAX));
        for sibling in &self.siblings {
            sibling.encode_to(out);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SparseMerkleSumUpdateV2 {
    pub domain: SparseStateDomainV2,
    pub key: Hash32,
    pub old_leaf: SparseMerkleSumLeafV2,
    pub new_leaf: SparseMerkleSumLeafV2,
    pub path: SparseMerkleSumPathV2,
    /// True only when this update reopens the key changed immediately before
    /// it in the same chained batch.
    pub continues_previous_key: bool,
}

impl CanonicalEncode for SparseMerkleSumUpdateV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.domain.encode_to(out);
        out.extend_from_slice(&self.key);
        self.old_leaf.encode_to(out);
        self.new_leaf.encode_to(out);
        self.path.encode_to(out);
        put_u8(out, u8::from(self.continues_previous_key));
    }
}

fn empty_leaf_hash_v2(domain: SparseStateDomainV2) -> Hash32 {
    tagged_hash(
        "ECX/incremental-sparse-empty-leaf/v1",
        &[SPARSE_MERKLE_SUM_VERSION_V2, domain.code()],
    )
}

pub(crate) fn present_leaf_hash_v2(
    domain: SparseStateDomainV2,
    key: Hash32,
    leaf: SparseMerkleSumLeafV2,
) -> Hash32 {
    let mut bytes = Vec::with_capacity(2 + 32 + leaf.canonical_bytes().len());
    put_u8(&mut bytes, SPARSE_MERKLE_SUM_VERSION_V2);
    domain.encode_to(&mut bytes);
    bytes.extend_from_slice(&key);
    leaf.encode_to(&mut bytes);
    tagged_hash("ECX/incremental-sparse-present-leaf/v1", &bytes)
}

pub(crate) fn parent_hash_v2(
    domain: SparseStateDomainV2,
    height: u16,
    left: SparseMerkleSumNodeV2,
    right: SparseMerkleSumNodeV2,
    combined: TraderAggregateV2,
) -> Hash32 {
    let mut bytes = Vec::with_capacity(4 + 3 * left.canonical_bytes().len());
    put_u8(&mut bytes, SPARSE_MERKLE_SUM_VERSION_V2);
    domain.encode_to(&mut bytes);
    put_u16(&mut bytes, height);
    left.encode_to(&mut bytes);
    right.encode_to(&mut bytes);
    combined.encode_to(&mut bytes);
    tagged_hash("ECX/incremental-sparse-parent/v1", &bytes)
}

pub(crate) fn canonical_empty_sparse_nodes_v2(
    domain: SparseStateDomainV2,
) -> Result<Vec<SparseMerkleSumNodeV2>, ProtocolError> {
    let mut nodes = Vec::with_capacity(SPARSE_MERKLE_SUM_DEPTH_V2 + 1);
    let mut node = SparseMerkleSumNodeV2 {
        hash: empty_leaf_hash_v2(domain),
        aggregate: TraderAggregateV2::ZERO,
    };
    nodes.push(node);
    for next_height in 1..=SPARSE_MERKLE_SUM_DEPTH_V2 {
        node = SparseMerkleSumNodeV2 {
            hash: parent_hash_v2(
                domain,
                u16::try_from(next_height).map_err(|_| ProtocolError::ArithmeticOverflow)?,
                node,
                node,
                TraderAggregateV2::ZERO,
            ),
            aggregate: TraderAggregateV2::ZERO,
        };
        nodes.push(node);
    }
    Ok(nodes)
}

pub fn canonical_empty_sparse_node_v2(
    domain: SparseStateDomainV2,
    height: usize,
) -> Result<SparseMerkleSumNodeV2, ProtocolError> {
    canonical_empty_sparse_nodes_v2(domain)?
        .get(height)
        .copied()
        .ok_or(ProtocolError::InvalidMerkleProof)
}

pub fn canonical_empty_sparse_root_v2(domain: SparseStateDomainV2) -> SparseMerkleSumRootV2 {
    let empty = canonical_empty_sparse_nodes_v2(domain).expect("the frozen sparse depth fits u16");
    SparseMerkleSumRootV2::from_node(domain, empty[SPARSE_MERKLE_SUM_DEPTH_V2])
}

pub fn canonical_empty_sparse_path_v2(domain: SparseStateDomainV2) -> SparseMerkleSumPathV2 {
    let mut siblings =
        canonical_empty_sparse_nodes_v2(domain).expect("the frozen sparse depth fits u16");
    siblings.pop();
    SparseMerkleSumPathV2 { domain, siblings }
}

fn key_bit_lsb_first(key: &Hash32, level: usize) -> bool {
    let byte = key[31 - (level / 8)];
    ((byte >> (level % 8)) & 1) == 1
}

fn validate_subtree_capacity(
    node: SparseMerkleSumNodeV2,
    height: usize,
) -> Result<(), ProtocolError> {
    if height < 128 && node.aggregate.leaf_count > (1u128 << height) {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    Ok(())
}

fn compute_sparse_root_v2(
    domain: SparseStateDomainV2,
    key: Hash32,
    leaf: SparseMerkleSumLeafV2,
    path: &SparseMerkleSumPathV2,
) -> Result<SparseMerkleSumRootV2, ProtocolError> {
    leaf.validate()?;
    if path.domain != domain || path.siblings.len() != SPARSE_MERKLE_SUM_DEPTH_V2 {
        return Err(ProtocolError::InvalidMerkleProof);
    }

    let mut current = SparseMerkleSumNodeV2 {
        hash: if leaf.present {
            present_leaf_hash_v2(domain, key, leaf)
        } else {
            empty_leaf_hash_v2(domain)
        },
        aggregate: leaf.aggregate,
    };
    for (level, sibling) in path.siblings.iter().copied().enumerate() {
        validate_subtree_capacity(sibling, level)?;
        let (left, right) = if key_bit_lsb_first(&key, level) {
            (sibling, current)
        } else {
            (current, sibling)
        };
        let combined = left.aggregate.checked_add(right.aggregate)?;
        current = SparseMerkleSumNodeV2 {
            hash: parent_hash_v2(
                domain,
                u16::try_from(level + 1).map_err(|_| ProtocolError::ArithmeticOverflow)?,
                left,
                right,
                combined,
            ),
            aggregate: combined,
        };
    }
    Ok(SparseMerkleSumRootV2::from_node(domain, current))
}

impl SparseMerkleSumUpdateV2 {
    fn verify_internal(
        &self,
        expected_old_root: SparseMerkleSumRootV2,
    ) -> Result<SparseMerkleSumRootV2, ProtocolError> {
        if self.domain != expected_old_root.domain
            || self.path.domain != self.domain
            || self.path.siblings.len() != SPARSE_MERKLE_SUM_DEPTH_V2
            || self.old_leaf == self.new_leaf
        {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        let actual_old = compute_sparse_root_v2(self.domain, self.key, self.old_leaf, &self.path)?;
        if actual_old != expected_old_root {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        compute_sparse_root_v2(self.domain, self.key, self.new_leaf, &self.path)
    }

    /// Generic single-key verification rejects trader-domain opaque leaves.
    /// Use the typed trader update APIs for that consensus domain.
    pub fn verify(
        &self,
        expected_old_root: SparseMerkleSumRootV2,
    ) -> Result<SparseMerkleSumRootV2, ProtocolError> {
        if self.domain == SparseStateDomainV2::Trader {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        self.verify_internal(expected_old_root)
    }
}

fn validate_sparse_update_batch_shape_v2(
    updates: &[SparseMerkleSumUpdateV2],
) -> Result<(), ProtocolError> {
    if updates.len() > MAX_SPARSE_MERKLE_SUM_UPDATES_PER_BATCH_V2
        || updates.iter().any(|update| {
            update.path.siblings.len() != SPARSE_MERKLE_SUM_DEPTH_V2
                || update.path.domain != update.domain
                || update.old_leaf == update.new_leaf
        })
    {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    Ok(())
}

pub fn canonical_sparse_update_batch_bytes_v2(
    updates: &[SparseMerkleSumUpdateV2],
) -> Result<Vec<u8>, ProtocolError> {
    validate_sparse_update_batch_shape_v2(updates)?;
    let mut bytes = Vec::new();
    put_u16(
        &mut bytes,
        u16::try_from(updates.len()).map_err(|_| ProtocolError::ArithmeticOverflow)?,
    );
    for update in updates {
        update.encode_to(&mut bytes);
    }
    if bytes.len() > MAX_CHAINED_SPARSE_MERKLE_SUM_UPDATE_BATCH_BYTES_V2 {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    Ok(bytes)
}

fn verify_chained_sparse_updates_internal_v2(
    initial_root: SparseMerkleSumRootV2,
    updates: &[SparseMerkleSumUpdateV2],
    maximum_updates: usize,
) -> Result<SparseMerkleSumRootV2, ProtocolError> {
    if maximum_updates == 0
        || maximum_updates > MAX_SPARSE_MERKLE_SUM_UPDATES_PER_BATCH_V2
        || updates.len() > maximum_updates
    {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    canonical_sparse_update_batch_bytes_v2(updates)?;

    let mut seen = BTreeSet::new();
    let mut previous_key = None;
    let mut root = initial_root;
    for update in updates {
        let seen_before = !seen.insert(update.key);
        let immediate_reopen = previous_key == Some(update.key);
        if update.continues_previous_key != immediate_reopen || (seen_before && !immediate_reopen) {
            return Err(ProtocolError::DuplicateMerkleKey);
        }
        root = update.verify_internal(root)?;
        previous_key = Some(update.key);
    }
    Ok(root)
}

pub fn verify_chained_sparse_updates_v2(
    initial_root: SparseMerkleSumRootV2,
    updates: &[SparseMerkleSumUpdateV2],
    maximum_updates: usize,
) -> Result<SparseMerkleSumRootV2, ProtocolError> {
    if initial_root.domain == SparseStateDomainV2::Trader
        || updates
            .iter()
            .any(|update| update.domain == SparseStateDomainV2::Trader)
    {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    verify_chained_sparse_updates_internal_v2(initial_root, updates, maximum_updates)
}

/// One unique-key leaf replacement inside a canonical shared-frontier batch.
/// Immediate repeated operations on one key are first checked as a logical
/// leaf chain, then coalesced to one old/new replacement for this tree proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SparseMerkleSumBatchLeafUpdateV2 {
    pub key: Hash32,
    pub old_leaf: SparseMerkleSumLeafV2,
    pub new_leaf: SparseMerkleSumLeafV2,
}

impl CanonicalEncode for SparseMerkleSumBatchLeafUpdateV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.key);
        self.old_leaf.encode_to(out);
        self.new_leaf.encode_to(out);
    }
}

/// Deterministic DFS frontier item.  Canonical empty siblings are represented
/// by one byte rather than a repeated 355-byte node. An occupied item equal
/// to the canonical empty node is rejected, so the encoding is unique.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
// Canonical consensus frontier stores the fixed node inline. Boxing would
// make the in-memory proof allocation-dependent without changing the exact
// wire encoding, and complicate guest review for no size benefit on the wire.
#[allow(clippy::large_enum_variant)]
pub enum SparseMerkleSumFrontierItemV2 {
    CanonicalEmpty,
    Occupied(SparseMerkleSumNodeV2),
}

impl CanonicalEncode for SparseMerkleSumFrontierItemV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        match self {
            Self::CanonicalEmpty => put_u8(out, 0),
            Self::Occupied(node) => {
                put_u8(out, 1);
                node.encode_to(out);
            }
        }
    }
}

/// Canonical shared-prefix sparse multiproof.
///
/// `updates` are strictly byte-lexicographically ordered by key.  `frontier`
/// is consumed in a deterministic left-first DFS: whenever a child subtree
/// contains no updated key, exactly one frontier item supplies that subtree.
/// This proves completeness—omitting or adding a subtree changes the old root
/// or leaves an unconsumed item.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SparseMerkleSumBatchProofV2 {
    pub domain: SparseStateDomainV2,
    pub updates: Vec<SparseMerkleSumBatchLeafUpdateV2>,
    pub frontier: Vec<SparseMerkleSumFrontierItemV2>,
}

impl CanonicalEncode for SparseMerkleSumBatchProofV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.domain.encode_to(out);
        put_u16(out, u16::try_from(self.updates.len()).unwrap_or(u16::MAX));
        for update in &self.updates {
            update.encode_to(out);
        }
        put_u16(out, u16::try_from(self.frontier.len()).unwrap_or(u16::MAX));
        for item in &self.frontier {
            item.encode_to(out);
        }
    }
}

fn root_bit_msb_first(key: &Hash32, depth: usize) -> bool {
    let byte = key[depth / 8];
    ((byte >> (7 - (depth % 8))) & 1) == 1
}

fn split_batch_updates_at_depth(
    updates: &[SparseMerkleSumBatchLeafUpdateV2],
    depth: usize,
) -> usize {
    updates.partition_point(|update| !root_bit_msb_first(&update.key, depth))
}

fn frontier_item_node_v2(
    canonical_empty_nodes: &[SparseMerkleSumNodeV2],
    subtree_height: usize,
    item: SparseMerkleSumFrontierItemV2,
) -> Result<SparseMerkleSumNodeV2, ProtocolError> {
    let empty = canonical_empty_nodes
        .get(subtree_height)
        .copied()
        .ok_or(ProtocolError::InvalidMerkleProof)?;
    match item {
        SparseMerkleSumFrontierItemV2::CanonicalEmpty => Ok(empty),
        SparseMerkleSumFrontierItemV2::Occupied(node) => {
            if node == empty || node.hash == empty.hash {
                return Err(ProtocolError::NonCanonicalEncoding);
            }
            validate_subtree_capacity(node, subtree_height)?;
            Ok(node)
        }
    }
}

fn compute_sparse_batch_subtree_v2(
    domain: SparseStateDomainV2,
    depth: usize,
    updates: &[SparseMerkleSumBatchLeafUpdateV2],
    frontier: &[SparseMerkleSumFrontierItemV2],
    frontier_cursor: &mut usize,
    canonical_empty_nodes: &[SparseMerkleSumNodeV2],
) -> Result<(SparseMerkleSumNodeV2, SparseMerkleSumNodeV2), ProtocolError> {
    #[derive(Debug, Clone, Copy)]
    enum Frame {
        Visit { depth: usize, lo: usize, hi: usize },
        Combine { depth: usize },
    }

    if depth > SPARSE_MERKLE_SUM_DEPTH_V2 || updates.is_empty() {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    let mut frames = vec![Frame::Visit {
        depth,
        lo: 0,
        hi: updates.len(),
    }];
    let mut results = Vec::new();
    while let Some(frame) = frames.pop() {
        match frame {
            Frame::Visit { depth, lo, hi } => {
                if depth > SPARSE_MERKLE_SUM_DEPTH_V2 || lo > hi || hi > updates.len() {
                    return Err(ProtocolError::InvalidMerkleProof);
                }
                if lo == hi {
                    let item = frontier
                        .get(*frontier_cursor)
                        .copied()
                        .ok_or(ProtocolError::UnexpectedEnd)?;
                    *frontier_cursor = frontier_cursor
                        .checked_add(1)
                        .ok_or(ProtocolError::ArithmeticOverflow)?;
                    let subtree_height = SPARSE_MERKLE_SUM_DEPTH_V2 - depth;
                    let node = frontier_item_node_v2(canonical_empty_nodes, subtree_height, item)?;
                    results.push((node, node));
                    continue;
                }
                if depth == SPARSE_MERKLE_SUM_DEPTH_V2 {
                    if hi - lo != 1 {
                        return Err(ProtocolError::InvalidMerkleProof);
                    }
                    let update = updates[lo];
                    update.old_leaf.validate()?;
                    update.new_leaf.validate()?;
                    if update.old_leaf == update.new_leaf {
                        return Err(ProtocolError::NonCanonicalEncoding);
                    }
                    let leaf_node = |leaf: SparseMerkleSumLeafV2| SparseMerkleSumNodeV2 {
                        hash: if leaf.present {
                            present_leaf_hash_v2(domain, update.key, leaf)
                        } else {
                            empty_leaf_hash_v2(domain)
                        },
                        aggregate: leaf.aggregate,
                    };
                    results.push((leaf_node(update.old_leaf), leaf_node(update.new_leaf)));
                    continue;
                }

                let split = lo + split_batch_updates_at_depth(&updates[lo..hi], depth);
                // LIFO order preserves the canonical left-first DFS and folds
                // only after both child results are available on the heap.
                frames.push(Frame::Combine { depth });
                frames.push(Frame::Visit {
                    depth: depth + 1,
                    lo: split,
                    hi,
                });
                frames.push(Frame::Visit {
                    depth: depth + 1,
                    lo,
                    hi: split,
                });
            }
            Frame::Combine { depth } => {
                let (old_right, new_right) =
                    results.pop().ok_or(ProtocolError::InvalidMerkleProof)?;
                let (old_left, new_left) =
                    results.pop().ok_or(ProtocolError::InvalidMerkleProof)?;
                let parent_height = u16::try_from(SPARSE_MERKLE_SUM_DEPTH_V2 - depth)
                    .map_err(|_| ProtocolError::ArithmeticOverflow)?;
                let old_aggregate = old_left.aggregate.checked_add(old_right.aggregate)?;
                let new_aggregate = new_left.aggregate.checked_add(new_right.aggregate)?;
                results.push((
                    SparseMerkleSumNodeV2 {
                        hash: parent_hash_v2(
                            domain,
                            parent_height,
                            old_left,
                            old_right,
                            old_aggregate,
                        ),
                        aggregate: old_aggregate,
                    },
                    SparseMerkleSumNodeV2 {
                        hash: parent_hash_v2(
                            domain,
                            parent_height,
                            new_left,
                            new_right,
                            new_aggregate,
                        ),
                        aggregate: new_aggregate,
                    },
                ));
            }
        }
    }
    if results.len() != 1 {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    results.pop().ok_or(ProtocolError::InvalidMerkleProof)
}

fn frontier_slot_count_v2(
    depth: usize,
    updates: &[SparseMerkleSumBatchLeafUpdateV2],
) -> Result<usize, ProtocolError> {
    if depth > SPARSE_MERKLE_SUM_DEPTH_V2 || updates.is_empty() {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    let mut frames = vec![(depth, 0usize, updates.len())];
    let mut slots = 0usize;
    while let Some((depth, lo, hi)) = frames.pop() {
        if depth > SPARSE_MERKLE_SUM_DEPTH_V2 || lo > hi || hi > updates.len() {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        if lo == hi {
            slots = slots
                .checked_add(1)
                .ok_or(ProtocolError::ArithmeticOverflow)?;
        } else if depth == SPARSE_MERKLE_SUM_DEPTH_V2 {
            if hi - lo != 1 {
                return Err(ProtocolError::InvalidMerkleProof);
            }
        } else {
            let split = lo + split_batch_updates_at_depth(&updates[lo..hi], depth);
            frames.push((depth + 1, split, hi));
            frames.push((depth + 1, lo, split));
        }
    }
    Ok(slots)
}

fn validate_batch_update_order_v2(
    updates: &[SparseMerkleSumBatchLeafUpdateV2],
) -> Result<(), ProtocolError> {
    if updates.is_empty()
        || updates.len() > MAX_SPARSE_MERKLE_SUM_UPDATES_PER_BATCH_V2
        || updates.windows(2).any(|pair| pair[0].key >= pair[1].key)
        || updates
            .iter()
            .any(|update| update.old_leaf == update.new_leaf)
    {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    Ok(())
}

impl SparseMerkleSumBatchProofV2 {
    /// Construct the unique all-empty frontier for insertions into a canonical
    /// empty root.  A populated root must supply authenticated occupied items.
    pub fn for_canonical_empty_root(
        domain: SparseStateDomainV2,
        updates: Vec<SparseMerkleSumBatchLeafUpdateV2>,
    ) -> Result<Self, ProtocolError> {
        validate_batch_update_order_v2(&updates)?;
        if updates.iter().any(|update| update.old_leaf.present) {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        let slots = frontier_slot_count_v2(0, &updates)?;
        Ok(Self {
            domain,
            updates,
            frontier: vec![SparseMerkleSumFrontierItemV2::CanonicalEmpty; slots],
        })
    }

    pub fn canonical_bytes_checked(&self) -> Result<Vec<u8>, ProtocolError> {
        validate_batch_update_order_v2(&self.updates)?;
        let expected_frontier = frontier_slot_count_v2(0, &self.updates)?;
        if self.frontier.len() != expected_frontier || self.frontier.len() > u16::MAX as usize {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        let bytes = self.canonical_bytes();
        if bytes.len() > MAX_SPARSE_MERKLE_SUM_UPDATE_BATCH_BYTES_V2 {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        Ok(bytes)
    }

    fn verify_internal(
        &self,
        expected_old_root: SparseMerkleSumRootV2,
    ) -> Result<SparseMerkleSumRootV2, ProtocolError> {
        if self.domain != expected_old_root.domain {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        self.canonical_bytes_checked()?;
        let canonical_empty_nodes = canonical_empty_sparse_nodes_v2(self.domain)?;
        let mut frontier_cursor = 0;
        let (old_node, new_node) = compute_sparse_batch_subtree_v2(
            self.domain,
            0,
            &self.updates,
            &self.frontier,
            &mut frontier_cursor,
            &canonical_empty_nodes,
        )?;
        if frontier_cursor != self.frontier.len()
            || SparseMerkleSumRootV2::from_node(self.domain, old_node) != expected_old_root
        {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        Ok(SparseMerkleSumRootV2::from_node(self.domain, new_node))
    }

    /// Verify a generic sparse-state batch. Trader-domain batches are rejected
    /// at this public boundary because an opaque commitment/aggregate pair is
    /// insufficient for consensus trader state; callers must use
    /// [`TraderStateBatchProofV2`], which opens and validates each trader leaf.
    pub fn verify(
        &self,
        expected_old_root: SparseMerkleSumRootV2,
    ) -> Result<SparseMerkleSumRootV2, ProtocolError> {
        if self.domain == SparseStateDomainV2::Trader {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        self.verify_internal(expected_old_root)
    }
}

/// Bounds that a future frozen successor configuration must commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IncrementalAccountingBoundsV2 {
    pub maximum_abs_trader_collateral_atoms: u128,
    pub maximum_total_controlled_atoms: u128,
    pub maximum_abs_position_atoms: u64,
    pub maximum_open_interest_atoms: u128,
    pub maximum_price_atoms: u64,
}

impl IncrementalAccountingBoundsV2 {
    /// Maximum gross integer trader cash reachable when every leaf in the
    /// complete frozen height/update namespace is present at its per-trader
    /// bound. This is intentionally distinct from physical controlled supply:
    /// opposing positive and negative trader balances can have a larger gross
    /// sum while their signed value remains conserved.
    pub fn maximum_reachable_gross_trader_cash_atoms(self) -> Result<u128, ProtocolError> {
        self.maximum_abs_trader_collateral_atoms
            .checked_mul(MAX_REACHABLE_INCREMENTAL_LEAF_COUNT_V2)
            .ok_or(ProtocolError::ArithmeticOverflow)
    }

    pub fn maximum_reachable_gross_exact_cash_numerator(self) -> Result<Uint256V2, ProtocolError> {
        Uint256V2::from_u128(self.maximum_reachable_gross_trader_cash_atoms()?)
            .checked_mul_u64(EXACT_ACCOUNTING_DENOMINATOR_V2)?
            .checked_add(
                Uint256V2::from_u128(MAX_REACHABLE_INCREMENTAL_LEAF_COUNT_V2)
                    .checked_mul_u64(EXACT_ACCOUNTING_DENOMINATOR_V2 - 1)?,
            )
    }

    pub fn maximum_reachable_abs_q_numerator(self) -> Result<Uint256V2, ProtocolError> {
        Uint256V2::from_u64(self.maximum_price_atoms)
            .checked_mul_u64(FUNDING_INDEX_DENOMINATOR_V2)?
            .checked_add(Uint256V2::from_u128(
                maximum_reachable_abs_funding_index_v2()?.unsigned_abs(),
            ))
    }

    pub fn validate(self) -> Result<(), ProtocolError> {
        if self.maximum_abs_trader_collateral_atoms == 0
            || self.maximum_total_controlled_atoms == 0
            || self.maximum_abs_position_atoms == 0
            || self.maximum_abs_position_atoms > i64::MAX as u64
            || self.maximum_open_interest_atoms == 0
            || self.maximum_open_interest_atoms > i128::MAX as u128
            || self.maximum_price_atoms == 0
            || self.maximum_abs_trader_collateral_atoms > self.maximum_total_controlled_atoms
            || self.maximum_total_controlled_atoms > i128::MAX as u128
        {
            return Err(ProtocolError::InvalidBondState);
        }
        let gross_open_interest = self
            .maximum_open_interest_atoms
            .checked_mul(2)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        let maximum_gross_trader_cash = self.maximum_reachable_gross_trader_cash_atoms()?;
        if maximum_gross_trader_cash > i128::MAX as u128 {
            return Err(ProtocolError::ArithmeticOverflow);
        }
        let maximum_exact_cash = self.maximum_reachable_gross_exact_cash_numerator()?;
        let maximum_mark_or_cost = Uint256V2::from_u128(gross_open_interest)
            .checked_mul_u64(self.maximum_price_atoms)?
            .checked_mul_u64(FUNDING_INDEX_DENOMINATOR_V2)?;
        let maximum_funding = Uint256V2::from_u128(gross_open_interest)
            .checked_mul_u128(maximum_reachable_abs_funding_index_v2()?.unsigned_abs())?;
        // Check the entire exact controlled-value expression, not only each
        // product, so every state inside the frozen OI/price/supply maxima has
        // a representable signed-256 conservation value.
        let maximum_expression = maximum_exact_cash
            .checked_add(maximum_mark_or_cost)?
            .checked_add(maximum_mark_or_cost)?
            .checked_add(maximum_funding)?
            .checked_add(maximum_funding)?;
        if maximum_expression.0 > SIGNED_256_MAX_MAGNITUDE_V2 {
            return Err(ProtocolError::ArithmeticOverflow);
        }
        Ok(())
    }
}

impl CanonicalEncode for IncrementalAccountingBoundsV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.maximum_abs_trader_collateral_atoms.to_be_bytes());
        out.extend_from_slice(&self.maximum_total_controlled_atoms.to_be_bytes());
        put_u64(out, self.maximum_abs_position_atoms);
        out.extend_from_slice(&self.maximum_open_interest_atoms.to_be_bytes());
        put_u64(out, self.maximum_price_atoms);
    }
}

/// One confidential trader/account/position/risk leaf.
///
/// `cash_residual_numerator` is the unique truncation-toward-zero remainder in
/// `(-D, D)`, where `D = PRICE_SCALE * 1_000_000`.  It is zero or has the same sign as integer
/// collateral (unless that quotient is zero).  Thus exact cash is
/// `collateral_atoms * D + cash_residual_numerator`; there is no
/// alternate signed representation of the same value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TraderLeafV2 {
    pub version: u8,
    pub trader: XOnlyKey,
    pub account_nonce: u128,
    pub collateral_atoms: i128,
    pub cash_residual_numerator: i64,
    pub position_size_atoms: i64,
    /// Exact signed cost at denominator D: `size * price * 1_000_000`.
    pub signed_cost_basis_numerator: Int256V2,
    /// Cumulative `sum(mark_price_atoms * rate_ppm)`.  This is not raw ppm.
    pub last_funding_index_numerator: i128,
    pub selected_initial_margin_bps: u32,
    pub order_generation: u128,
    pub salt: Hash32,
}

impl TraderLeafV2 {
    pub const VERSION: u8 = 1;

    pub fn key(&self) -> Hash32 {
        self.trader.0
    }

    pub fn validate(&self, bounds: IncrementalAccountingBoundsV2) -> Result<(), ProtocolError> {
        bounds.validate()?;
        XOnlyPublicKey::from_slice(&self.trader.0).map_err(|_| ProtocolError::InvalidBondState)?;
        if self.version != Self::VERSION
            || self.salt == [0; 32]
            || self.collateral_atoms.unsigned_abs() > bounds.maximum_abs_trader_collateral_atoms
            || self.cash_residual_numerator.unsigned_abs() >= EXACT_ACCOUNTING_DENOMINATOR_V2
            || self.position_size_atoms.unsigned_abs() > bounds.maximum_abs_position_atoms
            || !ALLOWED_INITIAL_MARGIN_BPS_V2.contains(&self.selected_initial_margin_bps)
        {
            return Err(ProtocolError::InvalidBondState);
        }
        if (self.collateral_atoms > 0 && self.cash_residual_numerator < 0)
            || (self.collateral_atoms < 0 && self.cash_residual_numerator > 0)
        {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        self.signed_cost_basis_numerator.validate()?;

        if self.position_size_atoms == 0 {
            if self.signed_cost_basis_numerator != Int256V2::ZERO
                || self.last_funding_index_numerator != 0
            {
                return Err(ProtocolError::InvalidBondState);
            }
        } else {
            validate_exact_funding_index_v2(self.last_funding_index_numerator)?;
            if self.signed_cost_basis_numerator == Int256V2::ZERO
                || self.signed_cost_basis_numerator.negative != (self.position_size_atoms < 0)
            {
                return Err(ProtocolError::InvalidBondState);
            }
            let size = Uint256V2::from_u64(self.position_size_atoms.unsigned_abs());
            let minimum_cost = size.checked_mul_u64(FUNDING_INDEX_DENOMINATOR_V2)?;
            let maximum_cost = size
                .checked_mul_u64(bounds.maximum_price_atoms)?
                .checked_mul_u64(FUNDING_INDEX_DENOMINATOR_V2)?;
            if self.signed_cost_basis_numerator.magnitude < minimum_cost
                || self.signed_cost_basis_numerator.magnitude > maximum_cost
            {
                return Err(ProtocolError::InvalidBondState);
            }
        }

        let exact_cash = self.exact_cash_numerator_unchecked()?;
        let maximum_exact_cash = Uint256V2::from_u128(bounds.maximum_abs_trader_collateral_atoms)
            .checked_mul_u64(EXACT_ACCOUNTING_DENOMINATOR_V2)?
            .checked_add(Uint256V2::from_u64(EXACT_ACCOUNTING_DENOMINATOR_V2 - 1))?;
        if exact_cash.magnitude > maximum_exact_cash {
            return Err(ProtocolError::InvalidBondState);
        }
        Ok(())
    }

    fn validated_commitment(
        &self,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<Hash32, ProtocolError> {
        self.validate(bounds)?;
        Ok(canonical_hash("ECX/incremental-trader-leaf/v1", self))
    }

    pub fn aggregate(
        &self,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<TraderAggregateV2, ProtocolError> {
        self.validate(bounds)?;
        let size = i128::from(self.position_size_atoms);
        let exact_cash = self.exact_cash_numerator_unchecked()?;
        let aggregate = TraderAggregateV2 {
            leaf_count: 1,
            total_collateral_atoms: self.collateral_atoms,
            gross_collateral_atoms: self.collateral_atoms.unsigned_abs(),
            net_position_atoms: size,
            long_open_interest_atoms: if size > 0 {
                u128::from(self.position_size_atoms.unsigned_abs())
            } else {
                0
            },
            short_open_interest_atoms: if size < 0 {
                u128::from(self.position_size_atoms.unsigned_abs())
            } else {
                0
            },
            signed_cost_basis_numerator: self.signed_cost_basis_numerator,
            gross_cost_basis_numerator: self.signed_cost_basis_numerator.magnitude,
            fractional_cash_numerator: Int256V2::from_i128(i128::from(
                self.cash_residual_numerator,
            )),
            gross_fractional_cash_numerator: Uint256V2::from_u64(
                self.cash_residual_numerator.unsigned_abs(),
            ),
            flat_negative_exact_cash_numerator: if size == 0 && exact_cash.is_negative() {
                exact_cash.magnitude
            } else {
                Uint256V2::ZERO
            },
            lazy_funding_checkpoint_numerator: Int256V2::checked_product_i64_i128(
                self.position_size_atoms,
                self.last_funding_index_numerator,
            )?,
            gross_lazy_funding_checkpoint_numerator: Uint256V2::from_u128(
                self.last_funding_index_numerator.unsigned_abs(),
            )
            .checked_mul_u64(self.position_size_atoms.unsigned_abs())?,
            minimum_selected_initial_margin_bps: self.selected_initial_margin_bps,
            maximum_selected_initial_margin_bps: self.selected_initial_margin_bps,
        };
        aggregate.validate(bounds)?;
        Ok(aggregate)
    }

    pub fn sparse_leaf(
        &self,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<SparseMerkleSumLeafV2, ProtocolError> {
        SparseMerkleSumLeafV2::present(self.validated_commitment(bounds)?, self.aggregate(bounds)?)
    }

    fn exact_cash_numerator_unchecked(&self) -> Result<Int256V2, ProtocolError> {
        Int256V2::from_i128(self.collateral_atoms)
            .checked_mul_u64(EXACT_ACCOUNTING_DENOMINATOR_V2)?
            .checked_add(Int256V2::from_i128(i128::from(
                self.cash_residual_numerator,
            )))
    }

    pub fn exact_cash_numerator(
        &self,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<Int256V2, ProtocolError> {
        self.validate(bounds)?;
        self.exact_cash_numerator_unchecked()
    }

    /// Apply an exact signed cash numerator and re-normalize to the unique
    /// truncation-toward-zero quotient/remainder representation.
    pub fn apply_exact_cash_delta_numerator(
        &mut self,
        delta_numerator: Int256V2,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<(), ProtocolError> {
        let mut next = self.clone();
        next.apply_exact_cash_delta_inner(delta_numerator, bounds)?;
        next.validate(bounds)?;
        *self = next;
        Ok(())
    }

    fn apply_exact_cash_delta_inner(
        &mut self,
        delta_numerator: Int256V2,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<(), ProtocolError> {
        let current = self.exact_cash_numerator(bounds)?;
        let next = current.checked_add(delta_numerator)?;
        let (collateral, residual) =
            next.div_rem_u64_toward_zero(EXACT_ACCOUNTING_DENOMINATOR_V2)?;
        self.collateral_atoms = collateral.try_to_i128()?;
        self.cash_residual_numerator =
            i64::try_from(residual).map_err(|_| ProtocolError::ArithmeticOverflow)?;
        Ok(())
    }

    /// Settle lazy funding exactly.  Positive growth in the global index means
    /// longs pay shorts, hence the negative sign on `size * index_delta`.
    pub fn settle_lazy_funding(
        &mut self,
        global_funding_index_numerator: i128,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<(), ProtocolError> {
        let mut next = self.clone();
        next.validate(bounds)?;
        if next.position_size_atoms == 0 {
            next.last_funding_index_numerator = 0;
        } else {
            let index_delta = global_funding_index_numerator
                .checked_sub(next.last_funding_index_numerator)
                .ok_or(ProtocolError::ArithmeticOverflow)?;
            let payment =
                Int256V2::checked_product_i64_i128(next.position_size_atoms, index_delta)?
                    .checked_neg()?;
            next.apply_exact_cash_delta_inner(payment, bounds)?;
            next.last_funding_index_numerator = global_funding_index_numerator;
        }
        next.validate(bounds)?;
        *self = next;
        Ok(())
    }

    /// Extract accrued funding for an ECX account without making a trade or
    /// crediting quote cash. The caller must stage this leaf and settle the
    /// returned liability in ECX atomically; this method alone moves no assets.
    pub fn settle_lazy_funding_for_ecx(
        &mut self,
        global_funding_index_numerator: i128,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<Int256V2, ProtocolError> {
        if self.collateral_atoms != 0 || self.cash_residual_numerator != 0 {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        let mut next = self.clone();
        next.validate(bounds)?;
        validate_exact_funding_index_v2(global_funding_index_numerator)?;
        let payment = if next.position_size_atoms == 0 {
            next.last_funding_index_numerator = 0;
            Int256V2::ZERO
        } else {
            let delta = global_funding_index_numerator
                .checked_sub(next.last_funding_index_numerator)
                .ok_or(ProtocolError::ArithmeticOverflow)?;
            let payment = Int256V2::checked_product_i64_i128(
                next.position_size_atoms, delta,
            )?.checked_neg()?;
            next.last_funding_index_numerator = global_funding_index_numerator;
            payment
        };
        next.validate(bounds)?;
        *self = next;
        Ok(payment)
    }

    /// Settle funding and apply one signed base-quantity delta at an exact
    /// price.  Partial close cost uses truncation toward zero; subtracting that
    /// quotient from the old cost retains the division remainder in the still
    /// open cost basis.
    pub fn apply_trade_exact(
        &mut self,
        position_delta_atoms: i64,
        fill_price_atoms: u64,
        global_funding_index_numerator: i128,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<Int256V2, ProtocolError> {
        self.apply_trade_settlement_inner(position_delta_atoms, fill_price_atoms,
            global_funding_index_numerator, bounds, true)
    }

    /// Position-engine entry point for ECX settlement. The leaf carries no
    /// quote cash; the returned exact quote delta includes BOTH realized P&L
    /// and lazy funding and must be settled in the versioned ECX account lane.
    /// No ECX is transferred here. Callers must commit the position and its
    /// asset settlement together, never this position mutation alone.
    pub fn apply_trade_for_ecx_settlement(
        &mut self,
        position_delta_atoms: i64,
        fill_price_atoms: u64,
        global_funding_index_numerator: i128,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<Int256V2, ProtocolError> {
        if self.collateral_atoms != 0 || self.cash_residual_numerator != 0 {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        self.apply_trade_settlement_inner(position_delta_atoms, fill_price_atoms,
            global_funding_index_numerator, bounds, false)
    }

    fn apply_trade_settlement_inner(
        &mut self,
        position_delta_atoms: i64,
        fill_price_atoms: u64,
        global_funding_index_numerator: i128,
        bounds: IncrementalAccountingBoundsV2,
        credit_quote_cash: bool,
    ) -> Result<Int256V2, ProtocolError> {
        if position_delta_atoms == 0 {
            return Err(ProtocolError::InvalidQuantity);
        }
        if fill_price_atoms == 0 || fill_price_atoms > bounds.maximum_price_atoms {
            return Err(ProtocolError::InvalidPrice);
        }

        let mut next = self.clone();
        next.validate(bounds)?;
        let funding_delta = if credit_quote_cash || next.position_size_atoms == 0 {
            Int256V2::ZERO
        } else {
            validate_exact_funding_index_v2(global_funding_index_numerator)?;
            Int256V2::checked_product_i64_i128(next.position_size_atoms,
                global_funding_index_numerator.checked_sub(next.last_funding_index_numerator)
                    .ok_or(ProtocolError::ArithmeticOverflow)?)?.checked_neg()?
        };
        if credit_quote_cash {
            next.settle_lazy_funding(global_funding_index_numerator, bounds)?;
        }
        let old_size = next.position_size_atoms;
        let new_size = old_size
            .checked_add(position_delta_atoms)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        if new_size.unsigned_abs() > bounds.maximum_abs_position_atoms {
            return Err(ProtocolError::InvalidQuantity);
        }
        let fill_cost =
            Int256V2::checked_product_i64_i128(position_delta_atoms, i128::from(fill_price_atoms))?
                .checked_mul_u64(FUNDING_INDEX_DENOMINATOR_V2)?;
        let mut realized_numerator = Int256V2::ZERO;

        if old_size == 0 || old_size.signum() == position_delta_atoms.signum() {
            next.signed_cost_basis_numerator =
                next.signed_cost_basis_numerator.checked_add(fill_cost)?;
        } else {
            let closing_atoms = old_size
                .unsigned_abs()
                .min(position_delta_atoms.unsigned_abs());
            let allocated_cost = next
                .signed_cost_basis_numerator
                .checked_mul_u64(closing_atoms)?
                .div_rem_u64_toward_zero(old_size.unsigned_abs())?
                .0;
            let closed_signed_size = if old_size > 0 {
                i64::try_from(closing_atoms).map_err(|_| ProtocolError::ArithmeticOverflow)?
            } else {
                -i64::try_from(closing_atoms).map_err(|_| ProtocolError::ArithmeticOverflow)?
            };
            realized_numerator = Int256V2::checked_product_i64_i128(
                closed_signed_size,
                i128::from(fill_price_atoms),
            )?
            .checked_mul_u64(FUNDING_INDEX_DENOMINATOR_V2)?
            .checked_sub(allocated_cost)?;

            next.signed_cost_basis_numerator = if new_size == 0 {
                Int256V2::ZERO
            } else if new_size.signum() == old_size.signum() {
                next.signed_cost_basis_numerator
                    .checked_sub(allocated_cost)?
            } else {
                Int256V2::checked_product_i64_i128(new_size, i128::from(fill_price_atoms))?
                    .checked_mul_u64(FUNDING_INDEX_DENOMINATOR_V2)?
            };
        }

        next.last_funding_index_numerator = if new_size == 0 {
            0
        } else {
            global_funding_index_numerator
        };
        next.position_size_atoms = new_size;
        if credit_quote_cash {
            next.apply_exact_cash_delta_inner(realized_numerator, bounds)?;
        }
        next.validate(bounds)?;
        let result = if credit_quote_cash { realized_numerator }
            else { realized_numerator.checked_add(funding_delta)? };
        *self = next;
        Ok(result)
    }
}

impl CanonicalEncode for TraderLeafV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        self.trader.encode_to(out);
        out.extend_from_slice(&self.account_nonce.to_be_bytes());
        put_i128(out, self.collateral_atoms);
        out.extend_from_slice(&self.cash_residual_numerator.to_be_bytes());
        out.extend_from_slice(&self.position_size_atoms.to_be_bytes());
        self.signed_cost_basis_numerator.encode_to(out);
        put_i128(out, self.last_funding_index_numerator);
        put_u32(out, self.selected_initial_margin_bps);
        out.extend_from_slice(&self.order_generation.to_be_bytes());
        out.extend_from_slice(&self.salt);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum IncrementalTraderMutationKindV2 {
    OrdinaryFill,
    Liquidation,
    FundingSettlement,
    Deposit,
    Withdrawal,
    BondSubscription,
    BondRecapitalization,
    BondRedemptionEnqueue,
    BondRedemptionCancellation,
    BondActionRejection,
    ForcedCancellation,
    ForcedReduceOnlyIoc,
    ForcedReduceOnlyIocFill,
}

impl CanonicalEncode for IncrementalTraderMutationKindV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(
            out,
            match self {
                Self::OrdinaryFill => 0,
                Self::Liquidation => 1,
                Self::FundingSettlement => 2,
                Self::Deposit => 3,
                Self::Withdrawal => 4,
                Self::BondSubscription => 5,
                Self::BondRecapitalization => 6,
                Self::BondRedemptionEnqueue => 7,
                Self::BondRedemptionCancellation => 8,
                Self::BondActionRejection => 9,
                Self::ForcedCancellation => 10,
                Self::ForcedReduceOnlyIoc => 11,
                Self::ForcedReduceOnlyIocFill => 12,
            },
        );
    }
}

/// One exact economic mutation applied to an authenticated trader leaf.
/// Other recursive children must derive and publish the same transcript root;
/// this object is not an authorization when supplied only by a host.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IncrementalTraderEconomicMutationV2 {
    pub kind: IncrementalTraderMutationKindV2,
    pub action_id: Hash32,
    pub exact_cash_delta_numerator: Int256V2,
    pub position_size_delta_atoms: i64,
    pub signed_cost_basis_delta_numerator: Int256V2,
    pub funding_checkpoint_after: Option<i128>,
    pub account_nonce_increment: u128,
    pub order_generation_increment: u128,
    pub selected_initial_margin_bps_after: Option<u32>,
}

impl CanonicalEncode for IncrementalTraderEconomicMutationV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.kind.encode_to(out);
        out.extend_from_slice(&self.action_id);
        self.exact_cash_delta_numerator.encode_to(out);
        out.extend_from_slice(&self.position_size_delta_atoms.to_be_bytes());
        self.signed_cost_basis_delta_numerator.encode_to(out);
        match self.funding_checkpoint_after {
            None => put_u8(out, 0),
            Some(value) => {
                put_u8(out, 1);
                put_i128(out, value);
            }
        }
        out.extend_from_slice(&self.account_nonce_increment.to_be_bytes());
        out.extend_from_slice(&self.order_generation_increment.to_be_bytes());
        match self.selected_initial_margin_bps_after {
            None => put_u8(out, 0),
            Some(value) => {
                put_u8(out, 1);
                out.extend_from_slice(&value.to_be_bytes());
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IncrementalTraderMutationChainV2 {
    pub trader: XOnlyKey,
    pub old_leaf: TraderLeafV2,
    pub mutations: Vec<IncrementalTraderEconomicMutationV2>,
    pub final_salt: Hash32,
    pub expected_new_leaf: TraderLeafV2,
}

/// Apply one already-authorized economic mutation to an authenticated trader
/// leaf.  Recursive action children use this exact helper to reconstruct the
/// state immediately before their own action rather than reimplementing cash,
/// nonce, position, funding, or margin arithmetic.
pub fn apply_incremental_trader_economic_mutation_v2(
    current: &TraderLeafV2,
    mutation: &IncrementalTraderEconomicMutationV2,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<TraderLeafV2, ProtocolError> {
    current.validate(bounds)?;
    if mutation.action_id == [0; 32] {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    let mut next = current.clone();
    next.apply_exact_cash_delta_inner(mutation.exact_cash_delta_numerator, bounds)?;
    next.position_size_atoms = next
        .position_size_atoms
        .checked_add(mutation.position_size_delta_atoms)
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    next.signed_cost_basis_numerator = next
        .signed_cost_basis_numerator
        .checked_add(mutation.signed_cost_basis_delta_numerator)?;
    if let Some(checkpoint) = mutation.funding_checkpoint_after {
        validate_exact_funding_index_v2(checkpoint)?;
        next.last_funding_index_numerator = checkpoint;
    }
    next.account_nonce = next
        .account_nonce
        .checked_add(mutation.account_nonce_increment)
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    next.order_generation = next
        .order_generation
        .checked_add(mutation.order_generation_increment)
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    if let Some(margin) = mutation.selected_initial_margin_bps_after {
        next.selected_initial_margin_bps = margin;
    }
    next.validate(bounds)?;
    Ok(next)
}

impl CanonicalEncode for IncrementalTraderMutationChainV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.trader.encode_to(out);
        self.old_leaf.encode_to(out);
        put_u16(out, u16::try_from(self.mutations.len()).unwrap_or(u16::MAX));
        for mutation in &self.mutations {
            mutation.encode_to(out);
        }
        out.extend_from_slice(&self.final_salt);
        self.expected_new_leaf.encode_to(out);
    }
}

pub fn verify_incremental_trader_mutation_chain_v2(
    chain: &IncrementalTraderMutationChainV2,
    bounds: IncrementalAccountingBoundsV2,
    maximum_mutations: usize,
) -> Result<Hash32, ProtocolError> {
    bounds.validate()?;
    chain.old_leaf.validate(bounds)?;
    if chain.trader != chain.old_leaf.trader
        || chain.trader != chain.expected_new_leaf.trader
        || chain.final_salt == [0; 32]
        || chain.mutations.is_empty()
        || chain.mutations.len() > maximum_mutations
        || maximum_mutations == 0
    {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    let mut seen = BTreeSet::new();
    let mut next = chain.old_leaf.clone();
    for mutation in &chain.mutations {
        if mutation.action_id == [0; 32] || !seen.insert(mutation.action_id) {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        next = apply_incremental_trader_economic_mutation_v2(&next, mutation, bounds)?;
    }
    next.salt = chain.final_salt;
    next.validate(bounds)?;
    if next != chain.expected_new_leaf {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    Ok(canonical_hash(
        "ECX/incremental-trader-economic-mutation-chain/v1",
        chain,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TraderStateUpdateV2 {
    pub trader: XOnlyKey,
    pub old_leaf: Option<TraderLeafV2>,
    pub new_leaf: Option<TraderLeafV2>,
    pub path: SparseMerkleSumPathV2,
    pub continues_previous_key: bool,
}

impl TraderStateUpdateV2 {
    fn sparse_update(
        &self,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<SparseMerkleSumUpdateV2, ProtocolError> {
        if self.old_leaf == self.new_leaf
            || self.path.domain != SparseStateDomainV2::Trader
            || self.path.siblings.len() != SPARSE_MERKLE_SUM_DEPTH_V2
        {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        for leaf in self.old_leaf.iter().chain(self.new_leaf.iter()) {
            if leaf.trader != self.trader {
                return Err(ProtocolError::InvalidMerkleProof);
            }
            leaf.validate(bounds)?;
        }
        Ok(SparseMerkleSumUpdateV2 {
            domain: SparseStateDomainV2::Trader,
            key: self.trader.0,
            old_leaf: match &self.old_leaf {
                Some(leaf) => leaf.sparse_leaf(bounds)?,
                None => SparseMerkleSumLeafV2::EMPTY,
            },
            new_leaf: match &self.new_leaf {
                Some(leaf) => leaf.sparse_leaf(bounds)?,
                None => SparseMerkleSumLeafV2::EMPTY,
            },
            path: self.path.clone(),
            continues_previous_key: self.continues_previous_key,
        })
    }
}

fn encode_optional_trader_leaf(out: &mut Vec<u8>, leaf: &Option<TraderLeafV2>) {
    match leaf {
        Some(value) => {
            put_u8(out, 1);
            value.encode_to(out);
        }
        None => put_u8(out, 0),
    }
}

/// One typed trader replacement inside a shared-frontier batch. Unlike the
/// generic sparse primitive, this object carries the opened old/new trader
/// leaves. Their key, commitment, and aggregate are derived inside the
/// verifier under the frozen accounting bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TraderStateBatchLeafUpdateV2 {
    pub trader: XOnlyKey,
    pub old_leaf: Option<TraderLeafV2>,
    pub new_leaf: Option<TraderLeafV2>,
}

impl TraderStateBatchLeafUpdateV2 {
    fn sparse_update(
        &self,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<SparseMerkleSumBatchLeafUpdateV2, ProtocolError> {
        if self.old_leaf == self.new_leaf {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        for leaf in self.old_leaf.iter().chain(self.new_leaf.iter()) {
            if leaf.trader != self.trader {
                return Err(ProtocolError::InvalidMerkleProof);
            }
            leaf.validate(bounds)?;
        }
        Ok(SparseMerkleSumBatchLeafUpdateV2 {
            key: self.trader.0,
            old_leaf: match &self.old_leaf {
                Some(leaf) => leaf.sparse_leaf(bounds)?,
                None => SparseMerkleSumLeafV2::EMPTY,
            },
            new_leaf: match &self.new_leaf {
                Some(leaf) => leaf.sparse_leaf(bounds)?,
                None => SparseMerkleSumLeafV2::EMPTY,
            },
        })
    }
}

impl CanonicalEncode for TraderStateBatchLeafUpdateV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.trader.encode_to(out);
        encode_optional_trader_leaf(out, &self.old_leaf);
        encode_optional_trader_leaf(out, &self.new_leaf);
    }
}

/// Typed shared-prefix trader proof. The domain is deliberately implicit and
/// fixed to `Trader`; callers cannot supply an opaque leaf commitment or
/// aggregate and cannot reuse this wrapper for another sparse-state domain.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TraderStateBatchProofV2 {
    pub updates: Vec<TraderStateBatchLeafUpdateV2>,
    pub frontier: Vec<SparseMerkleSumFrontierItemV2>,
}

impl CanonicalEncode for TraderStateBatchProofV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, SPARSE_MERKLE_SUM_VERSION_V2);
        SparseStateDomainV2::Trader.encode_to(out);
        put_u16(out, u16::try_from(self.updates.len()).unwrap_or(u16::MAX));
        for update in &self.updates {
            update.encode_to(out);
        }
        put_u16(out, u16::try_from(self.frontier.len()).unwrap_or(u16::MAX));
        for item in &self.frontier {
            item.encode_to(out);
        }
    }
}

impl TraderStateBatchProofV2 {
    fn sparse_proof(
        &self,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<SparseMerkleSumBatchProofV2, ProtocolError> {
        bounds.validate()?;
        if self.updates.is_empty()
            || self.updates.len() > MAX_SPARSE_MERKLE_SUM_UPDATES_PER_BATCH_V2
            || self.frontier.len() > u16::MAX as usize
        {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        for item in &self.frontier {
            if let SparseMerkleSumFrontierItemV2::Occupied(node) = item {
                node.aggregate.validate(bounds)?;
            }
        }
        let updates = self
            .updates
            .iter()
            .map(|update| update.sparse_update(bounds))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SparseMerkleSumBatchProofV2 {
            domain: SparseStateDomainV2::Trader,
            updates,
            frontier: self.frontier.clone(),
        })
    }

    /// Construct the canonical all-empty frontier for typed trader insertions.
    pub fn for_canonical_empty_root(
        updates: Vec<TraderStateBatchLeafUpdateV2>,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<Self, ProtocolError> {
        let sparse_updates = updates
            .iter()
            .map(|update| update.sparse_update(bounds))
            .collect::<Result<Vec<_>, _>>()?;
        let sparse = SparseMerkleSumBatchProofV2::for_canonical_empty_root(
            SparseStateDomainV2::Trader,
            sparse_updates,
        )?;
        let proof = Self {
            updates,
            frontier: sparse.frontier,
        };
        proof.canonical_bytes_checked(bounds)?;
        Ok(proof)
    }

    pub fn canonical_bytes_checked(
        &self,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<Vec<u8>, ProtocolError> {
        let sparse = self.sparse_proof(bounds)?;
        sparse.canonical_bytes_checked()?;
        let bytes = self.canonical_bytes();
        if bytes.len() > MAX_SPARSE_MERKLE_SUM_UPDATE_BATCH_BYTES_V2 {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        Ok(bytes)
    }

    pub fn verify(
        &self,
        expected_old_root: SparseMerkleSumRootV2,
        bounds: IncrementalAccountingBoundsV2,
        maximum_updates: usize,
    ) -> Result<SparseMerkleSumRootV2, ProtocolError> {
        if expected_old_root.domain != SparseStateDomainV2::Trader
            || maximum_updates == 0
            || maximum_updates > MAX_SPARSE_MERKLE_SUM_UPDATES_PER_BATCH_V2
            || self.updates.len() > maximum_updates
        {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        expected_old_root.aggregate.validate(bounds)?;
        self.canonical_bytes_checked(bounds)?;
        let next = self
            .sparse_proof(bounds)?
            .verify_internal(expected_old_root)?;
        next.aggregate.validate(bounds)?;
        Ok(next)
    }
}

impl CanonicalEncode for TraderStateUpdateV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.trader.encode_to(out);
        encode_optional_trader_leaf(out, &self.old_leaf);
        encode_optional_trader_leaf(out, &self.new_leaf);
        self.path.encode_to(out);
        put_u8(out, u8::from(self.continues_previous_key));
    }
}

pub fn canonical_trader_update_batch_bytes_v2(
    updates: &[TraderStateUpdateV2],
) -> Result<Vec<u8>, ProtocolError> {
    if updates.len() > MAX_SPARSE_MERKLE_SUM_UPDATES_PER_BATCH_V2
        || updates.iter().any(|update| {
            update.path.domain != SparseStateDomainV2::Trader
                || update.path.siblings.len() != SPARSE_MERKLE_SUM_DEPTH_V2
                || update.old_leaf == update.new_leaf
        })
    {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    let mut bytes = Vec::new();
    put_u16(
        &mut bytes,
        u16::try_from(updates.len()).map_err(|_| ProtocolError::ArithmeticOverflow)?,
    );
    for update in updates {
        update.encode_to(&mut bytes);
    }
    if bytes.len() > MAX_CHAINED_SPARSE_MERKLE_SUM_UPDATE_BATCH_BYTES_V2 {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    Ok(bytes)
}

pub fn verify_chained_trader_updates_v2(
    initial_root: SparseMerkleSumRootV2,
    updates: &[TraderStateUpdateV2],
    bounds: IncrementalAccountingBoundsV2,
    maximum_updates: usize,
) -> Result<SparseMerkleSumRootV2, ProtocolError> {
    bounds.validate()?;
    if initial_root.domain != SparseStateDomainV2::Trader
        || maximum_updates == 0
        || maximum_updates > MAX_SPARSE_MERKLE_SUM_UPDATES_PER_BATCH_V2
        || updates.len() > maximum_updates
    {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    initial_root.aggregate.validate(bounds)?;
    canonical_trader_update_batch_bytes_v2(updates)?;
    let sparse = updates
        .iter()
        .map(|update| update.sparse_update(bounds))
        .collect::<Result<Vec<_>, _>>()?;
    let next = verify_chained_sparse_updates_internal_v2(initial_root, &sparse, maximum_updates)?;
    next.aggregate.validate(bounds)?;
    Ok(next)
}

/// Require exact global position conservation and root-level OI consistency.
pub fn verify_balanced_trader_root_v2(
    root: SparseMerkleSumRootV2,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<(), ProtocolError> {
    if root.domain != SparseStateDomainV2::Trader {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    root.aggregate.validate(bounds)?;
    if root.aggregate.net_position_atoms != 0
        || root.aggregate.long_open_interest_atoms != root.aggregate.short_open_interest_atoms
    {
        return Err(ProtocolError::ConservationViolation);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DeficitSideV2 {
    Long,
    Short,
}

impl DeficitSideV2 {
    pub const fn code(self) -> u8 {
        match self {
            Self::Long => 1,
            Self::Short => 2,
        }
    }
}

impl CanonicalEncode for DeficitSideV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.code());
    }
}

/// Lexicographic representation with exactly the mathematical signed order.
/// Negative magnitudes are complemented, so `-2 < -1 < 0 < 1 < 2` without
/// narrowing the value to a host integer.
fn signed_numeric_order_key_unchecked_v2(value: Int256V2) -> [u8; 33] {
    let mut key = [0u8; 33];
    let magnitude = value.magnitude().to_be_bytes();
    if value.is_negative() {
        for (output, byte) in key[1..].iter_mut().zip(magnitude) {
            *output = !byte;
        }
    } else {
        key[0] = 1;
        key[1..].copy_from_slice(&magnitude);
    }
    key
}

pub fn signed_numeric_order_key_v2(value: Int256V2) -> Result<[u8; 33], ProtocolError> {
    value.validate()?;
    Ok(signed_numeric_order_key_unchecked_v2(value))
}

/// Funding-stable ordered key. Traders sharing one cut remain distinct, while
/// a strict range query always includes or excludes the complete cut bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DeficitIndexKeyV2 {
    pub cut_q_numerator: Int256V2,
    pub trader: XOnlyKey,
}

impl DeficitIndexKeyV2 {
    pub fn ordered_bytes(self) -> Result<[u8; DEFICIT_INDEX_KEY_BYTES_V2], ProtocolError> {
        self.cut_q_numerator.validate()?;
        XOnlyPublicKey::from_slice(&self.trader.0).map_err(|_| ProtocolError::InvalidBondState)?;
        let mut key = [0u8; DEFICIT_INDEX_KEY_BYTES_V2];
        key[..33].copy_from_slice(&signed_numeric_order_key_v2(self.cut_q_numerator)?);
        key[33..].copy_from_slice(&self.trader.0);
        Ok(key)
    }
}

impl Ord for DeficitIndexKeyV2 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.cut_q_numerator
            .cmp(&other.cut_q_numerator)
            .then_with(|| self.trader.0.cmp(&other.trader.0))
    }
}

impl PartialOrd for DeficitIndexKeyV2 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl CanonicalEncode for DeficitIndexKeyV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&signed_numeric_order_key_unchecked_v2(self.cut_q_numerator));
        self.trader.encode_to(out);
    }
}

/// One non-flat affine-equity line in a funding-stable ordered deficit index.
///
/// Let `Q = price * 1_000_000 - F` and
/// `C = exact_cash - signed_cost + position_size * last_F`.
/// For a long of size `s`, `intercept` is `K=-C` and the account is negative
/// iff `Q < ceil(K/s)`. For a short of magnitude `s`, `intercept` is `C` and
/// the account is negative iff `Q > floor(C/s)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DeficitIndexLeafV2 {
    pub version: u8,
    pub side: DeficitSideV2,
    pub trader: XOnlyKey,
    pub cut_q_numerator: Int256V2,
    pub size_atoms: u64,
    pub intercept_numerator: Int256V2,
    pub trader_leaf_commitment: Hash32,
}

impl DeficitIndexLeafV2 {
    pub const VERSION: u8 = 1;

    pub fn key(self) -> DeficitIndexKeyV2 {
        DeficitIndexKeyV2 {
            cut_q_numerator: self.cut_q_numerator,
            trader: self.trader,
        }
    }

    pub fn validate(self, bounds: IncrementalAccountingBoundsV2) -> Result<(), ProtocolError> {
        bounds.validate()?;
        XOnlyPublicKey::from_slice(&self.trader.0).map_err(|_| ProtocolError::InvalidBondState)?;
        self.cut_q_numerator.validate()?;
        self.intercept_numerator.validate()?;
        if self.version != Self::VERSION
            || self.size_atoms == 0
            || self.size_atoms > bounds.maximum_abs_position_atoms
            || self.trader_leaf_commitment == [0; 32]
        {
            return Err(ProtocolError::InvalidBondState);
        }
        let expected_cut = match self.side {
            DeficitSideV2::Long => self.intercept_numerator.ceil_div_u64(self.size_atoms)?,
            DeficitSideV2::Short => self.intercept_numerator.floor_div_u64(self.size_atoms)?,
        };
        if self.cut_q_numerator != expected_cut {
            return Err(ProtocolError::InvalidBondState);
        }
        let maximum_intercept = Uint256V2::from_u128(bounds.maximum_abs_trader_collateral_atoms)
            .checked_mul_u64(EXACT_ACCOUNTING_DENOMINATOR_V2)?
            .checked_add(Uint256V2::from_u64(EXACT_ACCOUNTING_DENOMINATOR_V2 - 1))?
            .checked_add(
                Uint256V2::from_u64(self.size_atoms)
                    .checked_mul_u64(bounds.maximum_price_atoms)?
                    .checked_mul_u64(FUNDING_INDEX_DENOMINATOR_V2)?,
            )?
            .checked_add(
                Uint256V2::from_u64(self.size_atoms)
                    .checked_mul_u128(maximum_reachable_abs_funding_index_v2()?.unsigned_abs())?,
            )?;
        if self.intercept_numerator.magnitude() > maximum_intercept {
            return Err(ProtocolError::InvalidBondState);
        }
        Ok(())
    }

    pub fn from_trader(
        trader: &TraderLeafV2,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<Option<Self>, ProtocolError> {
        trader.validate(bounds)?;
        if trader.position_size_atoms == 0 {
            return Ok(None);
        }
        let checkpoint = Int256V2::checked_product_i64_i128(
            trader.position_size_atoms,
            trader.last_funding_index_numerator,
        )?;
        let c = trader
            .exact_cash_numerator(bounds)?
            .checked_sub(trader.signed_cost_basis_numerator)?
            .checked_add(checkpoint)?;
        let (side, intercept_numerator) = if trader.position_size_atoms > 0 {
            (DeficitSideV2::Long, c.checked_neg()?)
        } else {
            (DeficitSideV2::Short, c)
        };
        let size_atoms = trader.position_size_atoms.unsigned_abs();
        let cut_q_numerator = match side {
            DeficitSideV2::Long => intercept_numerator.ceil_div_u64(size_atoms)?,
            DeficitSideV2::Short => intercept_numerator.floor_div_u64(size_atoms)?,
        };
        let line = Self {
            version: Self::VERSION,
            side,
            trader: trader.trader,
            cut_q_numerator,
            size_atoms,
            intercept_numerator,
            trader_leaf_commitment: trader.validated_commitment(bounds)?,
        };
        line.validate(bounds)?;
        Ok(Some(line))
    }

    pub fn verify_against_trader(
        self,
        trader: &TraderLeafV2,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<(), ProtocolError> {
        if Self::from_trader(trader, bounds)? != Some(self) {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        Ok(())
    }
}

impl CanonicalEncode for DeficitIndexLeafV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        self.side.encode_to(out);
        self.trader.encode_to(out);
        self.cut_q_numerator.encode_to(out);
        put_u64(out, self.size_atoms);
        self.intercept_numerator.encode_to(out);
        out.extend_from_slice(&self.trader_leaf_commitment);
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DeficitRangeAggregateV2 {
    pub leaf_count: u128,
    pub total_size_atoms: u128,
    /// Sum K for long lines; sum C for short lines.
    pub total_intercept_numerator: Int256V2,
}

impl DeficitRangeAggregateV2 {
    pub const ZERO: Self = Self {
        leaf_count: 0,
        total_size_atoms: 0,
        total_intercept_numerator: Int256V2::ZERO,
    };

    pub fn from_leaf(
        leaf: DeficitIndexLeafV2,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<Self, ProtocolError> {
        leaf.validate(bounds)?;
        Ok(Self {
            leaf_count: 1,
            total_size_atoms: u128::from(leaf.size_atoms),
            total_intercept_numerator: leaf.intercept_numerator,
        })
    }

    pub fn checked_add(self, rhs: Self) -> Result<Self, ProtocolError> {
        Ok(Self {
            leaf_count: self
                .leaf_count
                .checked_add(rhs.leaf_count)
                .ok_or(ProtocolError::ArithmeticOverflow)?,
            total_size_atoms: self
                .total_size_atoms
                .checked_add(rhs.total_size_atoms)
                .ok_or(ProtocolError::ArithmeticOverflow)?,
            total_intercept_numerator: self
                .total_intercept_numerator
                .checked_add(rhs.total_intercept_numerator)?,
        })
    }

    pub fn validate(self, bounds: IncrementalAccountingBoundsV2) -> Result<(), ProtocolError> {
        bounds.validate()?;
        self.total_intercept_numerator.validate()?;
        if self.leaf_count == 0 {
            return if self == Self::ZERO {
                Ok(())
            } else {
                Err(ProtocolError::InvalidBondState)
            };
        }
        if self.leaf_count > MAX_REACHABLE_INCREMENTAL_LEAF_COUNT_V2
            || self.total_size_atoms == 0
            || self.total_size_atoms > bounds.maximum_open_interest_atoms
        {
            return Err(ProtocolError::InvalidBondState);
        }
        let maximum_intercept = Uint256V2::from_u128(bounds.maximum_abs_trader_collateral_atoms)
            .checked_mul_u64(EXACT_ACCOUNTING_DENOMINATOR_V2)?
            .checked_add(Uint256V2::from_u64(EXACT_ACCOUNTING_DENOMINATOR_V2 - 1))?
            .checked_mul_u128(self.leaf_count)?
            .checked_add(
                Uint256V2::from_u128(self.total_size_atoms)
                    .checked_mul_u64(bounds.maximum_price_atoms)?
                    .checked_mul_u64(FUNDING_INDEX_DENOMINATOR_V2)?,
            )?
            .checked_add(
                Uint256V2::from_u128(self.total_size_atoms)
                    .checked_mul_u128(maximum_reachable_abs_funding_index_v2()?.unsigned_abs())?,
            )?;
        if self.total_intercept_numerator.magnitude() > maximum_intercept {
            return Err(ProtocolError::InvalidBondState);
        }
        Ok(())
    }

    pub fn deficit_numerator(
        self,
        side: DeficitSideV2,
        q_numerator: Int256V2,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<Uint256V2, ProtocolError> {
        self.validate(bounds)?;
        q_numerator.validate()?;
        if q_numerator.magnitude() > bounds.maximum_reachable_abs_q_numerator()? {
            return Err(ProtocolError::InvalidBondState);
        }
        let q_size = q_numerator.checked_mul_u128(self.total_size_atoms)?;
        let deficit = match side {
            DeficitSideV2::Long => self.total_intercept_numerator.checked_sub(q_size)?,
            DeficitSideV2::Short => q_size.checked_sub(self.total_intercept_numerator)?,
        };
        if deficit.is_negative() {
            return Err(ProtocolError::InvalidBondState);
        }
        Ok(deficit.magnitude())
    }
}

impl CanonicalEncode for DeficitRangeAggregateV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.leaf_count.to_be_bytes());
        out.extend_from_slice(&self.total_size_atoms.to_be_bytes());
        self.total_intercept_numerator.encode_to(out);
    }
}

const DEFICIT_INDEX_VERSION_V2: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DeficitIndexNodeV2 {
    pub hash: Hash32,
    pub aggregate: DeficitRangeAggregateV2,
}

impl CanonicalEncode for DeficitIndexNodeV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.hash);
        self.aggregate.encode_to(out);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DeficitIndexRootV2 {
    pub side: DeficitSideV2,
    pub hash: Hash32,
    pub aggregate: DeficitRangeAggregateV2,
}

impl DeficitIndexRootV2 {
    fn from_node(side: DeficitSideV2, node: DeficitIndexNodeV2) -> Self {
        Self {
            side,
            hash: node.hash,
            aggregate: node.aggregate,
        }
    }

    pub fn validate(self, bounds: IncrementalAccountingBoundsV2) -> Result<(), ProtocolError> {
        self.aggregate.validate(bounds)
    }
}

impl CanonicalEncode for DeficitIndexRootV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, DEFICIT_INDEX_VERSION_V2);
        self.side.encode_to(out);
        out.extend_from_slice(&self.hash);
        self.aggregate.encode_to(out);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[allow(clippy::large_enum_variant)]
pub enum DeficitIndexPathItemV2 {
    CanonicalEmpty,
    Occupied(DeficitIndexNodeV2),
}

impl CanonicalEncode for DeficitIndexPathItemV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        match self {
            Self::CanonicalEmpty => put_u8(out, 0),
            Self::Occupied(node) => {
                put_u8(out, 1);
                node.encode_to(out);
            }
        }
    }
}

fn deficit_index_empty_leaf_hash_v2(side: DeficitSideV2) -> Hash32 {
    tagged_hash(
        "ECX/incremental-deficit-index-empty-leaf/v1",
        &[DEFICIT_INDEX_VERSION_V2, side.code()],
    )
}

fn deficit_index_present_leaf_hash_v2(
    line: DeficitIndexLeafV2,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<Hash32, ProtocolError> {
    line.validate(bounds)?;
    let mut bytes = Vec::new();
    put_u8(&mut bytes, DEFICIT_INDEX_VERSION_V2);
    line.side.encode_to(&mut bytes);
    bytes.extend_from_slice(&line.key().ordered_bytes()?);
    line.encode_to(&mut bytes);
    Ok(tagged_hash(
        "ECX/incremental-deficit-index-present-leaf/v1",
        &bytes,
    ))
}

fn deficit_index_line_leaf_node_v2(
    line: DeficitIndexLeafV2,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<DeficitIndexNodeV2, ProtocolError> {
    Ok(DeficitIndexNodeV2 {
        hash: deficit_index_present_leaf_hash_v2(line, bounds)?,
        aggregate: DeficitRangeAggregateV2::from_leaf(line, bounds)?,
    })
}

fn deficit_index_parent_hash_v2(
    side: DeficitSideV2,
    height: u16,
    left: DeficitIndexNodeV2,
    right: DeficitIndexNodeV2,
    combined: DeficitRangeAggregateV2,
) -> Hash32 {
    let mut bytes = Vec::new();
    put_u8(&mut bytes, DEFICIT_INDEX_VERSION_V2);
    side.encode_to(&mut bytes);
    put_u16(&mut bytes, height);
    left.encode_to(&mut bytes);
    right.encode_to(&mut bytes);
    combined.encode_to(&mut bytes);
    tagged_hash("ECX/incremental-deficit-index-parent/v1", &bytes)
}

fn canonical_empty_deficit_index_nodes_v2(
    side: DeficitSideV2,
) -> Result<Vec<DeficitIndexNodeV2>, ProtocolError> {
    let mut nodes = Vec::with_capacity(DEFICIT_INDEX_DEPTH_V2 + 1);
    let mut node = DeficitIndexNodeV2 {
        hash: deficit_index_empty_leaf_hash_v2(side),
        aggregate: DeficitRangeAggregateV2::ZERO,
    };
    nodes.push(node);
    for height in 1..=DEFICIT_INDEX_DEPTH_V2 {
        node = DeficitIndexNodeV2 {
            hash: deficit_index_parent_hash_v2(
                side,
                u16::try_from(height).map_err(|_| ProtocolError::ArithmeticOverflow)?,
                node,
                node,
                DeficitRangeAggregateV2::ZERO,
            ),
            aggregate: DeficitRangeAggregateV2::ZERO,
        };
        nodes.push(node);
    }
    Ok(nodes)
}

pub fn canonical_empty_deficit_index_root_v2(
    side: DeficitSideV2,
) -> Result<DeficitIndexRootV2, ProtocolError> {
    let nodes = canonical_empty_deficit_index_nodes_v2(side)?;
    let node = nodes
        .get(DEFICIT_INDEX_DEPTH_V2)
        .copied()
        .ok_or(ProtocolError::InvalidMerkleProof)?;
    Ok(DeficitIndexRootV2::from_node(side, node))
}

pub fn canonical_empty_deficit_index_node_v2(
    side: DeficitSideV2,
    height: usize,
) -> Result<DeficitIndexNodeV2, ProtocolError> {
    canonical_empty_deficit_index_nodes_v2(side)?
        .get(height)
        .copied()
        .ok_or(ProtocolError::InvalidMerkleProof)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DeficitIndexMutationKindV2 {
    Remove,
    Insert,
}

impl DeficitIndexMutationKindV2 {
    const fn code(self) -> u8 {
        match self {
            Self::Remove => 0,
            Self::Insert => 1,
        }
    }
}

impl CanonicalEncode for DeficitIndexMutationKindV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.code());
    }
}

/// One typed ordered-index mutation.  The affine line, key, leaf commitment,
/// and Merkle-sum aggregate are derived from the opened trader leaf under the
/// accounting bounds.  Callers cannot supply an opaque deficit leaf.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DeficitIndexUpdateV2 {
    pub side: DeficitSideV2,
    pub kind: DeficitIndexMutationKindV2,
    pub trader_leaf: TraderLeafV2,
    pub siblings_root_to_leaf: Vec<DeficitIndexPathItemV2>,
}

#[cfg(test)]
impl CanonicalEncode for DeficitIndexUpdateV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, DEFICIT_INDEX_VERSION_V2);
        self.side.encode_to(out);
        self.kind.encode_to(out);
        self.trader_leaf.encode_to(out);
        put_u16(
            out,
            u16::try_from(self.siblings_root_to_leaf.len()).unwrap_or(u16::MAX),
        );
        for item in &self.siblings_root_to_leaf {
            item.encode_to(out);
        }
    }
}

#[cfg(test)]
impl DeficitIndexUpdateV2 {
    fn derived_line(
        &self,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<DeficitIndexLeafV2, ProtocolError> {
        let line = DeficitIndexLeafV2::from_trader(&self.trader_leaf, bounds)?
            .ok_or(ProtocolError::InvalidMerkleProof)?;
        if line.side != self.side {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        Ok(line)
    }

    pub fn canonical_bytes_checked(
        &self,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<Vec<u8>, ProtocolError> {
        bounds.validate()?;
        self.derived_line(bounds)?;
        if self.siblings_root_to_leaf.len() != DEFICIT_INDEX_DEPTH_V2 {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        let empty_nodes = canonical_empty_deficit_index_nodes_v2(self.side)?;
        for (depth, item) in self.siblings_root_to_leaf.iter().copied().enumerate() {
            deficit_index_path_item_node_v2(
                item,
                DEFICIT_INDEX_DEPTH_V2 - depth - 1,
                &empty_nodes,
                bounds,
            )?;
        }
        let bytes = self.canonical_bytes();
        if bytes.len() > MAX_DEFICIT_INDEX_UPDATE_BYTES_V2 {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        Ok(bytes)
    }

    fn compute_roots(
        &self,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<(DeficitIndexRootV2, DeficitIndexRootV2), ProtocolError> {
        self.canonical_bytes_checked(bounds)?;
        let line = self.derived_line(bounds)?;
        let key = line.key().ordered_bytes()?;
        let empty_nodes = canonical_empty_deficit_index_nodes_v2(self.side)?;
        let present = deficit_index_line_leaf_node_v2(line, bounds)?;
        let empty = empty_nodes[0];
        let (mut old, mut new) = match self.kind {
            DeficitIndexMutationKindV2::Remove => (present, empty),
            DeficitIndexMutationKindV2::Insert => (empty, present),
        };

        for depth in (0..DEFICIT_INDEX_DEPTH_V2).rev() {
            let sibling = deficit_index_path_item_node_v2(
                self.siblings_root_to_leaf[depth],
                DEFICIT_INDEX_DEPTH_V2 - depth - 1,
                &empty_nodes,
                bounds,
            )?;
            let bit = deficit_index_key_bit_msb_first_v2(&key, depth)?;
            let old_children = if bit { (sibling, old) } else { (old, sibling) };
            let new_children = if bit { (sibling, new) } else { (new, sibling) };
            let height = u16::try_from(DEFICIT_INDEX_DEPTH_V2 - depth)
                .map_err(|_| ProtocolError::ArithmeticOverflow)?;
            let old_aggregate = old_children
                .0
                .aggregate
                .checked_add(old_children.1.aggregate)?;
            old_aggregate.validate(bounds)?;
            old = DeficitIndexNodeV2 {
                hash: deficit_index_parent_hash_v2(
                    self.side,
                    height,
                    old_children.0,
                    old_children.1,
                    old_aggregate,
                ),
                aggregate: old_aggregate,
            };
            let new_aggregate = new_children
                .0
                .aggregate
                .checked_add(new_children.1.aggregate)?;
            new_aggregate.validate(bounds)?;
            new = DeficitIndexNodeV2 {
                hash: deficit_index_parent_hash_v2(
                    self.side,
                    height,
                    new_children.0,
                    new_children.1,
                    new_aggregate,
                ),
                aggregate: new_aggregate,
            };
        }
        Ok((
            DeficitIndexRootV2::from_node(self.side, old),
            DeficitIndexRootV2::from_node(self.side, new),
        ))
    }

    fn verify(
        &self,
        expected_old_root: DeficitIndexRootV2,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<DeficitIndexRootV2, ProtocolError> {
        expected_old_root.validate(bounds)?;
        if expected_old_root.side != self.side {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        let (actual_old_root, next_root) = self.compute_roots(bounds)?;
        if actual_old_root != expected_old_root {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        next_root.validate(bounds)?;
        Ok(next_root)
    }
}

/// Canonical private-witness encoding for a chained reference update batch.
/// This is intentionally not the future shared-frontier wire format.
#[cfg(test)]
fn canonical_deficit_index_update_batch_bytes_v2(
    updates: &[DeficitIndexUpdateV2],
    bounds: IncrementalAccountingBoundsV2,
) -> Result<Vec<u8>, ProtocolError> {
    bounds.validate()?;
    if updates.is_empty() || updates.len() > MAX_DEFICIT_INDEX_UPDATES_PER_BATCH_V2 {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    let mut bytes = Vec::new();
    put_u8(&mut bytes, DEFICIT_INDEX_VERSION_V2);
    put_u16(
        &mut bytes,
        u16::try_from(updates.len()).map_err(|_| ProtocolError::InvalidMerkleProof)?,
    );
    for update in updates {
        update.canonical_bytes_checked(bounds)?;
        update.encode_to(&mut bytes);
    }
    if bytes.len() > MAX_CHAINED_DEFICIT_INDEX_UPDATE_BATCH_BYTES_V2 {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    Ok(bytes)
}

/// Verify immediate old-root/new-root chaining for typed ordered-index
/// mutations.  Full paths make this a fail-closed arithmetic reference; the
/// successor still needs a compact shared frontier before activation.
#[cfg(test)]
fn verify_chained_deficit_index_updates_v2(
    initial_root: DeficitIndexRootV2,
    updates: &[DeficitIndexUpdateV2],
    bounds: IncrementalAccountingBoundsV2,
    maximum_updates: usize,
) -> Result<DeficitIndexRootV2, ProtocolError> {
    if maximum_updates == 0
        || maximum_updates > MAX_DEFICIT_INDEX_UPDATES_PER_BATCH_V2
        || updates.is_empty()
        || updates.len() > maximum_updates
    {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    canonical_deficit_index_update_batch_bytes_v2(updates, bounds)?;
    let mut root = initial_root;
    for update in updates {
        if update.side != initial_root.side {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        root = update.verify(root, bounds)?;
    }
    Ok(root)
}

/// One path-free typed mutation in the compact ordered-index shared frontier.
/// Its key, line commitment, and sum are derived from `trader_leaf`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DeficitIndexBatchMutationV2 {
    pub kind: DeficitIndexMutationKindV2,
    pub trader_leaf: TraderLeafV2,
}

impl CanonicalEncode for DeficitIndexBatchMutationV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.kind.encode_to(out);
        self.trader_leaf.encode_to(out);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DerivedDeficitIndexBatchMutationV2 {
    kind: DeficitIndexMutationKindV2,
    line: DeficitIndexLeafV2,
    key: [u8; DEFICIT_INDEX_KEY_BYTES_V2],
}

impl DeficitIndexBatchMutationV2 {
    fn derive(
        &self,
        side: DeficitSideV2,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<DerivedDeficitIndexBatchMutationV2, ProtocolError> {
        let line = DeficitIndexLeafV2::from_trader(&self.trader_leaf, bounds)?
            .ok_or(ProtocolError::InvalidMerkleProof)?;
        if line.side != side {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        Ok(DerivedDeficitIndexBatchMutationV2 {
            kind: self.kind,
            line,
            key: line.key().ordered_bytes()?,
        })
    }
}

/// Canonical shared-prefix ordered-index mutation proof. Mutations are sorted
/// by signed-numeric cut and trader key. One key may appear twice only as an
/// adjacent `Remove, Insert` replacement; all other keys are unique.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DeficitIndexBatchProofV2 {
    pub side: DeficitSideV2,
    pub mutations: Vec<DeficitIndexBatchMutationV2>,
    pub frontier: Vec<DeficitIndexPathItemV2>,
}

impl CanonicalEncode for DeficitIndexBatchProofV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, DEFICIT_INDEX_VERSION_V2);
        self.side.encode_to(out);
        put_u16(out, u16::try_from(self.mutations.len()).unwrap_or(u16::MAX));
        for mutation in &self.mutations {
            mutation.encode_to(out);
        }
        put_u32(out, u32::try_from(self.frontier.len()).unwrap_or(u32::MAX));
        for item in &self.frontier {
            item.encode_to(out);
        }
    }
}

fn derive_and_validate_deficit_batch_mutations_v2(
    side: DeficitSideV2,
    mutations: &[DeficitIndexBatchMutationV2],
    bounds: IncrementalAccountingBoundsV2,
) -> Result<Vec<DerivedDeficitIndexBatchMutationV2>, ProtocolError> {
    bounds.validate()?;
    if mutations.is_empty() || mutations.len() > MAX_DEFICIT_INDEX_UPDATES_PER_BATCH_V2 {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    let derived = mutations
        .iter()
        .map(|mutation| mutation.derive(side, bounds))
        .collect::<Result<Vec<_>, _>>()?;
    for pair in derived.windows(2) {
        if pair[0].key > pair[1].key {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        if pair[0].key == pair[1].key
            && (pair[0].kind != DeficitIndexMutationKindV2::Remove
                || pair[1].kind != DeficitIndexMutationKindV2::Insert
                || pair[0].line == pair[1].line)
        {
            return Err(ProtocolError::DuplicateMerkleKey);
        }
    }
    // A valid equal-key pair is exactly Remove,Insert. Therefore any third
    // occurrence necessarily makes one adjacent pair invalid above.
    Ok(derived)
}

fn split_deficit_batch_at_depth_v2(
    mutations: &[DerivedDeficitIndexBatchMutationV2],
    depth: usize,
) -> Result<usize, ProtocolError> {
    if depth >= DEFICIT_INDEX_DEPTH_V2 {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    let mut split = 0;
    while split < mutations.len()
        && !deficit_index_key_bit_msb_first_v2(&mutations[split].key, depth)?
    {
        split += 1;
    }
    Ok(split)
}

fn deficit_batch_frontier_slot_count_v2(
    mutations: &[DerivedDeficitIndexBatchMutationV2],
) -> Result<usize, ProtocolError> {
    if mutations.is_empty() {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    let mut frames = vec![(0usize, 0usize, mutations.len())];
    let mut slots = 0usize;
    while let Some((depth, lo, hi)) = frames.pop() {
        if depth > DEFICIT_INDEX_DEPTH_V2 || lo > hi || hi > mutations.len() {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        if lo == hi {
            slots = slots
                .checked_add(1)
                .ok_or(ProtocolError::ArithmeticOverflow)?;
            if slots > MAX_DEFICIT_INDEX_SHARED_FRONTIER_ITEMS_V2 {
                return Err(ProtocolError::InvalidMerkleProof);
            }
        } else if depth == DEFICIT_INDEX_DEPTH_V2 {
            if hi - lo > 2
                || (hi - lo == 2
                    && (mutations[lo].key != mutations[lo + 1].key
                        || mutations[lo].kind != DeficitIndexMutationKindV2::Remove
                        || mutations[lo + 1].kind != DeficitIndexMutationKindV2::Insert))
            {
                return Err(ProtocolError::InvalidMerkleProof);
            }
        } else {
            let split = lo + split_deficit_batch_at_depth_v2(&mutations[lo..hi], depth)?;
            frames.push((depth + 1, split, hi));
            frames.push((depth + 1, lo, split));
        }
    }
    Ok(slots)
}

fn deficit_batch_leaf_nodes_v2(
    side: DeficitSideV2,
    mutations: &[DerivedDeficitIndexBatchMutationV2],
    empty_leaf: DeficitIndexNodeV2,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<(DeficitIndexNodeV2, DeficitIndexNodeV2), ProtocolError> {
    match mutations {
        [mutation] => {
            let present = deficit_index_line_leaf_node_v2(mutation.line, bounds)?;
            Ok(match mutation.kind {
                DeficitIndexMutationKindV2::Remove => (present, empty_leaf),
                DeficitIndexMutationKindV2::Insert => (empty_leaf, present),
            })
        }
        [remove, insert]
            if remove.key == insert.key
                && remove.line.side == side
                && insert.line.side == side
                && remove.kind == DeficitIndexMutationKindV2::Remove
                && insert.kind == DeficitIndexMutationKindV2::Insert
                && remove.line != insert.line =>
        {
            Ok((
                deficit_index_line_leaf_node_v2(remove.line, bounds)?,
                deficit_index_line_leaf_node_v2(insert.line, bounds)?,
            ))
        }
        _ => Err(ProtocolError::InvalidMerkleProof),
    }
}

fn compute_deficit_batch_subtree_v2(
    side: DeficitSideV2,
    mutations: &[DerivedDeficitIndexBatchMutationV2],
    frontier: &[DeficitIndexPathItemV2],
    bounds: IncrementalAccountingBoundsV2,
) -> Result<(DeficitIndexNodeV2, DeficitIndexNodeV2), ProtocolError> {
    #[derive(Debug, Clone, Copy)]
    enum Frame {
        Visit { depth: usize, lo: usize, hi: usize },
        Combine { depth: usize },
    }

    let empty_nodes = canonical_empty_deficit_index_nodes_v2(side)?;
    let mut frames = vec![Frame::Visit {
        depth: 0,
        lo: 0,
        hi: mutations.len(),
    }];
    let mut results = Vec::new();
    let mut frontier_cursor = 0usize;
    while let Some(frame) = frames.pop() {
        match frame {
            Frame::Visit { depth, lo, hi } => {
                if depth > DEFICIT_INDEX_DEPTH_V2 || lo > hi || hi > mutations.len() {
                    return Err(ProtocolError::InvalidMerkleProof);
                }
                if lo == hi {
                    let item = frontier
                        .get(frontier_cursor)
                        .copied()
                        .ok_or(ProtocolError::UnexpectedEnd)?;
                    frontier_cursor = frontier_cursor
                        .checked_add(1)
                        .ok_or(ProtocolError::ArithmeticOverflow)?;
                    let node = deficit_index_path_item_node_v2(
                        item,
                        DEFICIT_INDEX_DEPTH_V2 - depth,
                        &empty_nodes,
                        bounds,
                    )?;
                    results.push((node, node));
                } else if depth == DEFICIT_INDEX_DEPTH_V2 {
                    results.push(deficit_batch_leaf_nodes_v2(
                        side,
                        &mutations[lo..hi],
                        empty_nodes[0],
                        bounds,
                    )?);
                } else {
                    let split = lo + split_deficit_batch_at_depth_v2(&mutations[lo..hi], depth)?;
                    frames.push(Frame::Combine { depth });
                    frames.push(Frame::Visit {
                        depth: depth + 1,
                        lo: split,
                        hi,
                    });
                    frames.push(Frame::Visit {
                        depth: depth + 1,
                        lo,
                        hi: split,
                    });
                }
            }
            Frame::Combine { depth } => {
                let (old_right, new_right) =
                    results.pop().ok_or(ProtocolError::InvalidMerkleProof)?;
                let (old_left, new_left) =
                    results.pop().ok_or(ProtocolError::InvalidMerkleProof)?;
                let height = u16::try_from(DEFICIT_INDEX_DEPTH_V2 - depth)
                    .map_err(|_| ProtocolError::ArithmeticOverflow)?;
                let old_aggregate = old_left.aggregate.checked_add(old_right.aggregate)?;
                old_aggregate.validate(bounds)?;
                let new_aggregate = new_left.aggregate.checked_add(new_right.aggregate)?;
                new_aggregate.validate(bounds)?;
                results.push((
                    DeficitIndexNodeV2 {
                        hash: deficit_index_parent_hash_v2(
                            side,
                            height,
                            old_left,
                            old_right,
                            old_aggregate,
                        ),
                        aggregate: old_aggregate,
                    },
                    DeficitIndexNodeV2 {
                        hash: deficit_index_parent_hash_v2(
                            side,
                            height,
                            new_left,
                            new_right,
                            new_aggregate,
                        ),
                        aggregate: new_aggregate,
                    },
                ));
            }
        }
    }
    if frontier_cursor != frontier.len() || results.len() != 1 {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    results.pop().ok_or(ProtocolError::InvalidMerkleProof)
}

impl DeficitIndexBatchProofV2 {
    /// Construct the unique all-empty frontier. Every mutation must be an
    /// insertion because no present leaf exists in the canonical empty root.
    pub fn for_canonical_empty_root(
        side: DeficitSideV2,
        mutations: Vec<DeficitIndexBatchMutationV2>,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<Self, ProtocolError> {
        let derived = derive_and_validate_deficit_batch_mutations_v2(side, &mutations, bounds)?;
        if derived
            .iter()
            .any(|mutation| mutation.kind != DeficitIndexMutationKindV2::Insert)
        {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        let slots = deficit_batch_frontier_slot_count_v2(&derived)?;
        let proof = Self {
            side,
            mutations,
            frontier: vec![DeficitIndexPathItemV2::CanonicalEmpty; slots],
        };
        proof.canonical_bytes_checked(bounds)?;
        Ok(proof)
    }

    pub fn canonical_bytes_checked(
        &self,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<Vec<u8>, ProtocolError> {
        let derived =
            derive_and_validate_deficit_batch_mutations_v2(self.side, &self.mutations, bounds)?;
        let expected_frontier = deficit_batch_frontier_slot_count_v2(&derived)?;
        if self.frontier.len() != expected_frontier
            || self.frontier.len() > MAX_DEFICIT_INDEX_SHARED_FRONTIER_ITEMS_V2
        {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        // Exact subtree heights are checked again during iterative traversal;
        // this pre-pass rejects malformed aggregates before wire allocation.
        for item in &self.frontier {
            if let DeficitIndexPathItemV2::Occupied(node) = item {
                node.aggregate.validate(bounds)?;
                if node.aggregate.leaf_count == 0 {
                    return Err(ProtocolError::NonCanonicalEncoding);
                }
            }
        }
        let bytes = self.canonical_bytes();
        if bytes.len() > MAX_SHARED_DEFICIT_INDEX_UPDATE_BATCH_BYTES_V2 {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        Ok(bytes)
    }

    fn verify_internal(
        &self,
        expected_old_root: DeficitIndexRootV2,
        bounds: IncrementalAccountingBoundsV2,
        maximum_updates: usize,
    ) -> Result<DeficitIndexRootV2, ProtocolError> {
        if expected_old_root.side != self.side
            || maximum_updates == 0
            || maximum_updates > MAX_DEFICIT_INDEX_UPDATES_PER_BATCH_V2
            || self.mutations.len() > maximum_updates
        {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        expected_old_root.validate(bounds)?;
        self.canonical_bytes_checked(bounds)?;
        let derived =
            derive_and_validate_deficit_batch_mutations_v2(self.side, &self.mutations, bounds)?;
        let (old, new) =
            compute_deficit_batch_subtree_v2(self.side, &derived, &self.frontier, bounds)?;
        if DeficitIndexRootV2::from_node(self.side, old) != expected_old_root {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        let next = DeficitIndexRootV2::from_node(self.side, new);
        next.validate(bounds)?;
        Ok(next)
    }
}

fn deficit_index_key_bit_msb_first_v2(
    key: &[u8; DEFICIT_INDEX_KEY_BYTES_V2],
    depth: usize,
) -> Result<bool, ProtocolError> {
    if depth >= DEFICIT_INDEX_DEPTH_V2 {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    Ok(((key[depth / 8] >> (7 - depth % 8)) & 1) == 1)
}

fn deficit_index_boundary_key_v2(
    side: DeficitSideV2,
    q_numerator: Int256V2,
) -> Result<[u8; DEFICIT_INDEX_KEY_BYTES_V2], ProtocolError> {
    let mut key = [0u8; DEFICIT_INDEX_KEY_BYTES_V2];
    key[..33].copy_from_slice(&signed_numeric_order_key_v2(q_numerator)?);
    if side == DeficitSideV2::Long {
        key[33..].fill(0xff);
    }
    Ok(key)
}

fn validate_deficit_subtree_capacity_v2(
    node: DeficitIndexNodeV2,
    height: usize,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<(), ProtocolError> {
    node.aggregate.validate(bounds)?;
    if height < 128 && node.aggregate.leaf_count > (1u128 << height) {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    Ok(())
}

fn deficit_index_path_item_node_v2(
    item: DeficitIndexPathItemV2,
    subtree_height: usize,
    canonical_empty_nodes: &[DeficitIndexNodeV2],
    bounds: IncrementalAccountingBoundsV2,
) -> Result<DeficitIndexNodeV2, ProtocolError> {
    let empty = canonical_empty_nodes
        .get(subtree_height)
        .copied()
        .ok_or(ProtocolError::InvalidMerkleProof)?;
    match item {
        DeficitIndexPathItemV2::CanonicalEmpty => Ok(empty),
        DeficitIndexPathItemV2::Occupied(node) => {
            if node == empty || node.hash == empty.hash || node.aggregate.leaf_count == 0 {
                return Err(ProtocolError::NonCanonicalEncoding);
            }
            validate_deficit_subtree_capacity_v2(node, subtree_height, bounds)?;
            Ok(node)
        }
    }
}

/// Root-to-leaf nonmembership path at the strict range sentinel. Long proofs
/// use `(Q, ff..ff)` and aggregate the strict suffix; short proofs use
/// `(Q, 00..00)` and aggregate the strict prefix. Neither sentinel is a valid
/// x-only trader key, so a typed deficit leaf can never occupy the query key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DeficitIndexRangeProofV2 {
    pub side: DeficitSideV2,
    pub q_numerator: Int256V2,
    pub siblings_root_to_leaf: Vec<DeficitIndexPathItemV2>,
}

impl CanonicalEncode for DeficitIndexRangeProofV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, DEFICIT_INDEX_VERSION_V2);
        self.side.encode_to(out);
        self.q_numerator.encode_to(out);
        put_u16(
            out,
            u16::try_from(self.siblings_root_to_leaf.len()).unwrap_or(u16::MAX),
        );
        for item in &self.siblings_root_to_leaf {
            item.encode_to(out);
        }
    }
}

impl DeficitIndexRangeProofV2 {
    pub fn for_canonical_empty_root(
        side: DeficitSideV2,
        q_numerator: Int256V2,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<Self, ProtocolError> {
        bounds.validate()?;
        q_numerator.validate()?;
        if q_numerator.magnitude() > bounds.maximum_reachable_abs_q_numerator()? {
            return Err(ProtocolError::InvalidBondState);
        }
        let proof = Self {
            side,
            q_numerator,
            siblings_root_to_leaf: vec![
                DeficitIndexPathItemV2::CanonicalEmpty;
                DEFICIT_INDEX_DEPTH_V2
            ],
        };
        proof.canonical_bytes_checked()?;
        Ok(proof)
    }

    pub fn canonical_bytes_checked(&self) -> Result<Vec<u8>, ProtocolError> {
        self.q_numerator.validate()?;
        if self.siblings_root_to_leaf.len() != DEFICIT_INDEX_DEPTH_V2 {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        let bytes = self.canonical_bytes();
        if bytes.len() > MAX_DEFICIT_INDEX_RANGE_PROOF_BYTES_V2 {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        Ok(bytes)
    }

    fn compute(
        &self,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<(DeficitIndexRootV2, DeficitRangeAggregateV2), ProtocolError> {
        bounds.validate()?;
        self.canonical_bytes_checked()?;
        if self.q_numerator.magnitude() > bounds.maximum_reachable_abs_q_numerator()? {
            return Err(ProtocolError::InvalidBondState);
        }
        let key = deficit_index_boundary_key_v2(self.side, self.q_numerator)?;
        let empty_nodes = canonical_empty_deficit_index_nodes_v2(self.side)?;
        let mut sibling_nodes = Vec::with_capacity(DEFICIT_INDEX_DEPTH_V2);
        let mut selected = DeficitRangeAggregateV2::ZERO;
        for (depth, item) in self.siblings_root_to_leaf.iter().copied().enumerate() {
            let subtree_height = DEFICIT_INDEX_DEPTH_V2 - depth - 1;
            let sibling =
                deficit_index_path_item_node_v2(item, subtree_height, &empty_nodes, bounds)?;
            let bit = deficit_index_key_bit_msb_first_v2(&key, depth)?;
            let select_sibling = match self.side {
                DeficitSideV2::Long => !bit,
                DeficitSideV2::Short => bit,
            };
            if select_sibling {
                selected = selected.checked_add(sibling.aggregate)?;
            }
            sibling_nodes.push(sibling);
        }
        selected.validate(bounds)?;
        selected.deficit_numerator(self.side, self.q_numerator, bounds)?;

        let mut current = empty_nodes[0];
        for depth in (0..DEFICIT_INDEX_DEPTH_V2).rev() {
            let sibling = sibling_nodes[depth];
            let (left, right) = if deficit_index_key_bit_msb_first_v2(&key, depth)? {
                (sibling, current)
            } else {
                (current, sibling)
            };
            let aggregate = left.aggregate.checked_add(right.aggregate)?;
            aggregate.validate(bounds)?;
            current = DeficitIndexNodeV2 {
                hash: deficit_index_parent_hash_v2(
                    self.side,
                    u16::try_from(DEFICIT_INDEX_DEPTH_V2 - depth)
                        .map_err(|_| ProtocolError::ArithmeticOverflow)?,
                    left,
                    right,
                    aggregate,
                ),
                aggregate,
            };
        }
        Ok((DeficitIndexRootV2::from_node(self.side, current), selected))
    }

    pub fn verify(
        &self,
        expected_root: DeficitIndexRootV2,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<DeficitRangeAggregateV2, ProtocolError> {
        expected_root.validate(bounds)?;
        if self.side != expected_root.side {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        let (actual_root, selected) = self.compute(bounds)?;
        if actual_root != expected_root {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        Ok(selected)
    }
}

/// Verify two endpoint range proofs against one deficit-index root. Canonical
/// empty paths share one 520-level empty-root derivation instead of rebuilding
/// the same ladder and root for each endpoint. Any occupied path item falls
/// back to the complete independent verifier.
pub fn verify_deficit_index_range_pair_v2(
    expected_root: DeficitIndexRootV2,
    first: &DeficitIndexRangeProofV2,
    second: &DeficitIndexRangeProofV2,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<[DeficitRangeAggregateV2; 2], ProtocolError> {
    bounds.validate()?;
    expected_root.validate(bounds)?;
    if first.side != expected_root.side || second.side != expected_root.side {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    let all_empty = |proof: &DeficitIndexRangeProofV2| {
        proof
            .siblings_root_to_leaf
            .iter()
            .all(|item| matches!(item, DeficitIndexPathItemV2::CanonicalEmpty))
    };
    if all_empty(first) && all_empty(second) {
        for proof in [first, second] {
            proof.canonical_bytes_checked()?;
            proof.q_numerator.validate()?;
            if proof.q_numerator.magnitude() > bounds.maximum_reachable_abs_q_numerator()? {
                return Err(ProtocolError::InvalidBondState);
            }
        }
        if expected_root != canonical_empty_deficit_index_root_v2(expected_root.side)? {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        return Ok([DeficitRangeAggregateV2::ZERO; 2]);
    }
    Ok([
        first.verify(expected_root, bounds)?,
        second.verify(expected_root, bounds)?,
    ])
}

/// Validate a canonical ordered line list and aggregate the exact strict range
/// selected at Q. This is the arithmetic reference for a future authenticated
/// ordered range multiproof; it is not itself that missing tree proof.
pub fn aggregate_eligible_deficit_lines_v2(
    side: DeficitSideV2,
    q_numerator: Int256V2,
    lines: &[DeficitIndexLeafV2],
    bounds: IncrementalAccountingBoundsV2,
) -> Result<DeficitRangeAggregateV2, ProtocolError> {
    bounds.validate()?;
    q_numerator.validate()?;
    if q_numerator.magnitude() > bounds.maximum_reachable_abs_q_numerator()? {
        return Err(ProtocolError::InvalidBondState);
    }
    let mut previous = None;
    let mut aggregate = DeficitRangeAggregateV2::ZERO;
    for line in lines {
        line.validate(bounds)?;
        let key = line.key();
        if line.side != side || previous.is_some_and(|old| old >= key) {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        previous = Some(key);
        let eligible = match side {
            DeficitSideV2::Long => line.cut_q_numerator > q_numerator,
            DeficitSideV2::Short => line.cut_q_numerator < q_numerator,
        };
        if eligible {
            aggregate =
                aggregate.checked_add(DeficitRangeAggregateV2::from_leaf(*line, bounds)?)?;
        }
    }
    aggregate.validate(bounds)?;
    Ok(aggregate)
}

pub fn price_funding_q_numerator_v2(
    price_atoms: u64,
    global_funding_index_numerator: i128,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<Int256V2, ProtocolError> {
    bounds.validate()?;
    validate_exact_funding_index_v2(global_funding_index_numerator)?;
    if price_atoms == 0 || price_atoms > bounds.maximum_price_atoms {
        return Err(ProtocolError::InvalidPrice);
    }
    Int256V2::from_u128(u128::from(price_atoms) * u128::from(FUNDING_INDEX_DENOMINATOR_V2))
        .checked_sub(Int256V2::from_i128(global_funding_index_numerator))
}

/// Exact successor equity for one authenticated trader leaf at an
/// authenticated mark and global funding index. The result uses denominator
/// `PRICE_SCALE * 1_000_000` and does not truncate unrealized PnL or funding.
pub fn trader_equity_numerator_v2(
    trader: &TraderLeafV2,
    mark_price_atoms: u64,
    global_funding_index_numerator: i128,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<Int256V2, ProtocolError> {
    trader.validate(bounds)?;
    let q = price_funding_q_numerator_v2(mark_price_atoms, global_funding_index_numerator, bounds)?;
    let mut position_q = q.checked_mul_u64(trader.position_size_atoms.unsigned_abs())?;
    if trader.position_size_atoms < 0 {
        position_q = position_q.checked_neg()?;
    }
    trader
        .exact_cash_numerator(bounds)?
        .checked_sub(trader.signed_cost_basis_numerator)?
        .checked_add(position_q)?
        .checked_add(Int256V2::checked_product_i64_i128(
            trader.position_size_atoms,
            trader.last_funding_index_numerator,
        )?)
}

/// Exact permissionless-liquidation predicate for the fresh successor.
///
/// This preserves the finite relation's nested outward rounding: quote
/// notional is first ceiled to whole quote atoms, then maintenance margin is
/// ceiled at basis-point precision. Equity itself remains exact at denominator
/// D, eliminating per-position unrealized-PnL truncation.
pub fn is_incremental_trader_liquidatable_v2(
    trader: &TraderLeafV2,
    adverse_price_atoms: u64,
    global_funding_index_numerator: i128,
    maintenance_margin_bps: u32,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<bool, ProtocolError> {
    if trader.position_size_atoms == 0
        || maintenance_margin_bps == 0
        || maintenance_margin_bps >= 10_000
    {
        return Err(ProtocolError::InvalidRate);
    }
    let price_quantity = u128::from(adverse_price_atoms)
        .checked_mul(u128::from(trader.position_size_atoms.unsigned_abs()))
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    let notional_atoms = price_quantity
        .checked_add(u128::from(PRICE_SCALE - 1))
        .ok_or(ProtocolError::ArithmeticOverflow)?
        / u128::from(PRICE_SCALE);
    let margin_atoms = notional_atoms
        .checked_mul(u128::from(maintenance_margin_bps))
        .and_then(|value| value.checked_add(9_999))
        .ok_or(ProtocolError::ArithmeticOverflow)?
        / 10_000;
    let required =
        Int256V2::from_u128(margin_atoms).checked_mul_u64(EXACT_ACCOUNTING_DENOMINATOR_V2)?;
    Ok(trader_equity_numerator_v2(
        trader,
        adverse_price_atoms,
        global_funding_index_numerator,
        bounds,
    )? < required)
}

/// Add flat bad debt exactly once, then outward-ceil the complete selected
/// numerator once. Per-trader rounding is deliberately forbidden.
pub fn portfolio_deficit_atoms_v2(
    long_eligible: DeficitRangeAggregateV2,
    short_eligible: DeficitRangeAggregateV2,
    flat_negative_exact_cash_numerator: Uint256V2,
    q_numerator: Int256V2,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<Uint256V2, ProtocolError> {
    bounds.validate()?;
    if flat_negative_exact_cash_numerator > bounds.maximum_reachable_gross_exact_cash_numerator()? {
        return Err(ProtocolError::InvalidBondState);
    }
    let numerator = long_eligible
        .deficit_numerator(DeficitSideV2::Long, q_numerator, bounds)?
        .checked_add(short_eligible.deficit_numerator(
            DeficitSideV2::Short,
            q_numerator,
            bounds,
        )?)?
        .checked_add(flat_negative_exact_cash_numerator)?;
    let (quotient, remainder) = numerator.div_rem_u64(EXACT_ACCOUNTING_DENOMINATOR_V2)?;
    if remainder == 0 {
        Ok(quotient)
    } else {
        quotient.checked_add(Uint256V2::from_u64(1))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TraderDeficitUpdateLinkV2 {
    pub trader: XOnlyKey,
    pub old_line: Option<DeficitIndexLeafV2>,
    pub new_line: Option<DeficitIndexLeafV2>,
}

impl CanonicalEncode for TraderDeficitUpdateLinkV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.trader.encode_to(out);
        for line in [&self.old_line, &self.new_line] {
            match line {
                Some(value) => {
                    put_u8(out, 1);
                    value.encode_to(out);
                }
                None => put_u8(out, 0),
            }
        }
    }
}

/// Require one exact deficit remove/add projection for every typed trader
/// replacement, in the same canonical batch order.
pub fn verify_trader_deficit_update_links_v2(
    trader_updates: &[TraderStateBatchLeafUpdateV2],
    links: &[TraderDeficitUpdateLinkV2],
    bounds: IncrementalAccountingBoundsV2,
) -> Result<(), ProtocolError> {
    bounds.validate()?;
    if trader_updates.len() != links.len() {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    for (update, link) in trader_updates.iter().zip(links) {
        if update.trader != link.trader
            || link.old_line
                != update
                    .old_leaf
                    .as_ref()
                    .map(|leaf| DeficitIndexLeafV2::from_trader(leaf, bounds))
                    .transpose()?
                    .flatten()
            || link.new_line
                != update
                    .new_leaf
                    .as_ref()
                    .map(|leaf| DeficitIndexLeafV2::from_trader(leaf, bounds))
                    .transpose()?
                    .flatten()
        {
            return Err(ProtocolError::InvalidMerkleProof);
        }
    }
    Ok(())
}

#[cfg(test)]
fn verify_deficit_index_projection_side_v2(
    side: DeficitSideV2,
    actual: &[DeficitIndexUpdateV2],
    expected: &[(DeficitIndexMutationKindV2, TraderLeafV2)],
    bounds: IncrementalAccountingBoundsV2,
) -> Result<(), ProtocolError> {
    if actual.len() != expected.len() {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    for (update, (kind, trader_leaf)) in actual.iter().zip(expected) {
        update.canonical_bytes_checked(bounds)?;
        if update.side != side || update.kind != *kind || update.trader_leaf != *trader_leaf {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        update.derived_line(bounds)?;
    }
    Ok(())
}

/// Bind the two ordered deficit-index mutation streams one-to-one to a typed
/// trader shared-frontier batch.  Each old non-flat leaf is removed before
/// the corresponding new non-flat leaf is inserted.  Per-side order follows
/// the canonical trader batch order, so no mutation can be omitted, added,
/// reordered, or substituted without rejection.
#[cfg(test)]
fn verify_trader_deficit_index_update_projection_v2(
    trader_updates: &[TraderStateBatchLeafUpdateV2],
    long_updates: &[DeficitIndexUpdateV2],
    short_updates: &[DeficitIndexUpdateV2],
    bounds: IncrementalAccountingBoundsV2,
) -> Result<(), ProtocolError> {
    bounds.validate()?;
    if trader_updates.is_empty()
        || trader_updates.len() > MAX_SPARSE_MERKLE_SUM_UPDATES_PER_BATCH_V2
    {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    let mut previous_trader = None;
    let mut expected_long = Vec::new();
    let mut expected_short = Vec::new();
    for trader_update in trader_updates {
        trader_update.sparse_update(bounds)?;
        if previous_trader.is_some_and(|previous| previous >= trader_update.trader.0) {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        previous_trader = Some(trader_update.trader.0);
        for (kind, leaf) in [
            (
                DeficitIndexMutationKindV2::Remove,
                trader_update.old_leaf.as_ref(),
            ),
            (
                DeficitIndexMutationKindV2::Insert,
                trader_update.new_leaf.as_ref(),
            ),
        ] {
            let Some(leaf) = leaf else {
                continue;
            };
            let Some(line) = DeficitIndexLeafV2::from_trader(leaf, bounds)? else {
                continue;
            };
            match line.side {
                DeficitSideV2::Long => expected_long.push((kind, leaf.clone())),
                DeficitSideV2::Short => expected_short.push((kind, leaf.clone())),
            }
        }
    }
    verify_deficit_index_projection_side_v2(
        DeficitSideV2::Long,
        long_updates,
        &expected_long,
        bounds,
    )?;
    verify_deficit_index_projection_side_v2(
        DeficitSideV2::Short,
        short_updates,
        &expected_short,
        bounds,
    )
}

fn verify_deficit_batch_projection_side_v2(
    side: DeficitSideV2,
    proof: Option<&DeficitIndexBatchProofV2>,
    expected: Vec<DeficitIndexBatchMutationV2>,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<(), ProtocolError> {
    let mut keyed = expected
        .into_iter()
        .map(|mutation| {
            let derived = mutation.derive(side, bounds)?;
            Ok((derived.key, derived.kind.code(), mutation))
        })
        .collect::<Result<Vec<_>, ProtocolError>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    let expected = keyed
        .into_iter()
        .map(|(_, _, mutation)| mutation)
        .collect::<Vec<_>>();
    match (proof, expected.is_empty()) {
        (None, true) => Ok(()),
        (Some(proof), false) => {
            proof.canonical_bytes_checked(bounds)?;
            if proof.side != side || proof.mutations != expected {
                return Err(ProtocolError::InvalidMerkleProof);
            }
            Ok(())
        }
        _ => Err(ProtocolError::InvalidMerkleProof),
    }
}

/// Bind compact shared-prefix long/short mutation proofs exactly to the typed
/// trader shared-frontier batch. The index mutations are independently sorted
/// by ordered index key, while their opened trader leaves must match the
/// complete remove/insert projection of every trader replacement.
fn verify_trader_deficit_index_batch_projection_v2(
    trader_updates: &[TraderStateBatchLeafUpdateV2],
    long_proof: Option<&DeficitIndexBatchProofV2>,
    short_proof: Option<&DeficitIndexBatchProofV2>,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<(), ProtocolError> {
    bounds.validate()?;
    if trader_updates.is_empty()
        || trader_updates.len() > MAX_SPARSE_MERKLE_SUM_UPDATES_PER_BATCH_V2
    {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    let mut previous_trader = None;
    let mut long = Vec::new();
    let mut short = Vec::new();
    for trader_update in trader_updates {
        trader_update.sparse_update(bounds)?;
        if previous_trader.is_some_and(|previous| previous >= trader_update.trader.0) {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        previous_trader = Some(trader_update.trader.0);
        for (kind, leaf) in [
            (
                DeficitIndexMutationKindV2::Remove,
                trader_update.old_leaf.as_ref(),
            ),
            (
                DeficitIndexMutationKindV2::Insert,
                trader_update.new_leaf.as_ref(),
            ),
        ] {
            let Some(leaf) = leaf else {
                continue;
            };
            let Some(line) = DeficitIndexLeafV2::from_trader(leaf, bounds)? else {
                continue;
            };
            let mutation = DeficitIndexBatchMutationV2 {
                kind,
                trader_leaf: leaf.clone(),
            };
            match line.side {
                DeficitSideV2::Long => long.push(mutation),
                DeficitSideV2::Short => short.push(mutation),
            }
        }
    }
    verify_deficit_batch_projection_side_v2(DeficitSideV2::Long, long_proof, long, bounds)?;
    verify_deficit_batch_projection_side_v2(DeficitSideV2::Short, short_proof, short, bounds)
}

/// Consensus-safe compact deficit-index update boundary. It first binds both
/// optional proof streams exactly to the complete typed trader batch, then
/// verifies their authenticated old roots and returns the two next roots.
/// Callers cannot verify an unrelated typed deficit mutation through a public
/// raw-tree API.
pub fn verify_trader_deficit_index_batches_v2(
    trader_updates: &[TraderStateBatchLeafUpdateV2],
    old_long_root: DeficitIndexRootV2,
    old_short_root: DeficitIndexRootV2,
    long_proof: Option<&DeficitIndexBatchProofV2>,
    short_proof: Option<&DeficitIndexBatchProofV2>,
    bounds: IncrementalAccountingBoundsV2,
    maximum_updates: usize,
) -> Result<(DeficitIndexRootV2, DeficitIndexRootV2), ProtocolError> {
    if old_long_root.side != DeficitSideV2::Long
        || old_short_root.side != DeficitSideV2::Short
        || maximum_updates == 0
        || maximum_updates > MAX_DEFICIT_INDEX_UPDATES_PER_BATCH_V2
    {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    old_long_root.validate(bounds)?;
    old_short_root.validate(bounds)?;
    verify_trader_deficit_index_batch_projection_v2(
        trader_updates,
        long_proof,
        short_proof,
        bounds,
    )?;
    let next_long = match long_proof {
        Some(proof) => proof.verify_internal(old_long_root, bounds, maximum_updates)?,
        None => old_long_root,
    };
    let next_short = match short_proof {
        Some(proof) => proof.verify_internal(old_short_root, bounds, maximum_updates)?,
        None => old_short_root,
    };
    Ok((next_long, next_short))
}

/// Add one eight-hour funding observation to the exact lifetime index.
/// The index unit is `mark_price_atoms * rate_ppm`, not raw ppm.  Therefore
/// `-size * (next - last)` is an exact cash numerator at denominator
/// `PRICE_SCALE * 1_000_000`, matching the legacy one-epoch formula without
/// truncating per epoch.
pub fn advance_exact_funding_index_v2(
    previous_index_numerator: i128,
    mark_price_atoms: u64,
    funding_rate_ppm: i32,
) -> Result<i128, ProtocolError> {
    validate_exact_funding_index_v2(previous_index_numerator)?;
    if mark_price_atoms == 0 || funding_rate_ppm.unsigned_abs() > MAX_ABS_FUNDING_RATE_PPM_V2 as u32
    {
        return Err(ProtocolError::InvalidRate);
    }
    let delta = i128::from(mark_price_atoms)
        .checked_mul(i128::from(funding_rate_ppm))
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    let next = previous_index_numerator
        .checked_add(delta)
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    validate_exact_funding_index_v2(next)?;
    Ok(next)
}

/// Absolute maximum reachable lifetime funding index across the full `u64`
/// parent-MTP namespace, assuming at most one settlement per frozen eight-hour
/// epoch. This proof is intentionally independent of a deploy-time cap.
pub fn maximum_reachable_abs_funding_index_v2() -> Result<i128, ProtocolError> {
    let maximum_epochs = u128::from(u64::MAX / crate::funding_v2::FUNDING_EPOCH_SECONDS)
        .checked_add(1)
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    let maximum = maximum_epochs
        .checked_mul(u128::from(u64::MAX))
        .and_then(|value| value.checked_mul(u128::from(MAX_ABS_FUNDING_RATE_PPM_V2 as u32)))
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    i128::try_from(maximum).map_err(|_| ProtocolError::ArithmeticOverflow)
}

/// Enforce the arithmetic reachability envelope implied by the full `u64`
/// parent-MTP namespace. This is not a deploy-time lifetime cap: no valid
/// sequence with at most one settlement per eight-hour epoch can exceed it.
pub fn validate_exact_funding_index_v2(index_numerator: i128) -> Result<(), ProtocolError> {
    if index_numerator.unsigned_abs() > maximum_reachable_abs_funding_index_v2()?.unsigned_abs() {
        Err(ProtocolError::ArithmeticOverflow)
    } else {
        Ok(())
    }
}

/// Exact controlled-value numerator at a mark and global funding index.
///
/// The result is scaled by `PRICE_SCALE * 1_000_000`; callers compare it to
/// exact deposits minus withdrawals under their successor transition relation.
pub fn controlled_value_numerator_v2(
    trader_root: SparseMerkleSumRootV2,
    mark_price_atoms: u64,
    global_funding_index_numerator: i128,
    insurance_reserve_atoms: u128,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<Int256V2, ProtocolError> {
    verify_balanced_trader_root_v2(trader_root, bounds)?;
    validate_exact_funding_index_v2(global_funding_index_numerator)?;
    if mark_price_atoms == 0 || mark_price_atoms > bounds.maximum_price_atoms {
        return Err(ProtocolError::InvalidBondState);
    }
    // Gross trader cash is an arithmetic cancellation bound, not physical
    // supply: winners and debtors can make it exceed controlled USDD while
    // signed value remains conserved. Reserve is an actual controlled asset
    // and therefore is individually bounded by the frozen physical maximum.
    if insurance_reserve_atoms > bounds.maximum_total_controlled_atoms {
        return Err(ProtocolError::InvalidBondState);
    }
    let collateral = Int256V2::from_i128(trader_root.aggregate.total_collateral_atoms)
        .checked_mul_u64(EXACT_ACCOUNTING_DENOMINATOR_V2)?;
    let reserve = Int256V2::from_u128(insurance_reserve_atoms)
        .checked_mul_u64(EXACT_ACCOUNTING_DENOMINATOR_V2)?;
    let fractional = trader_root.aggregate.fractional_cash_numerator;
    let mark_term = Int256V2::from_i128(trader_root.aggregate.net_position_atoms)
        .checked_mul_u64(mark_price_atoms)?
        .checked_mul_u64(FUNDING_INDEX_DENOMINATOR_V2)?;
    let funding_term = Int256V2::from_i128(trader_root.aggregate.net_position_atoms)
        .checked_mul_i128(global_funding_index_numerator)?;
    collateral
        .checked_add(reserve)?
        .checked_add(fractional)?
        .checked_add(mark_term)?
        .checked_sub(trader_root.aggregate.signed_cost_basis_numerator)?
        .checked_sub(funding_term)?
        .checked_add(trader_root.aggregate.lazy_funding_checkpoint_numerator)
}

pub fn verify_controlled_value_v2(
    trader_root: SparseMerkleSumRootV2,
    mark_price_atoms: u64,
    global_funding_index_numerator: i128,
    insurance_reserve_atoms: u128,
    expected_controlled_value_numerator: Int256V2,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<(), ProtocolError> {
    expected_controlled_value_numerator.validate()?;
    let maximum_expected = Uint256V2::from_u128(bounds.maximum_total_controlled_atoms)
        .checked_mul_u64(EXACT_ACCOUNTING_DENOMINATOR_V2)?;
    if expected_controlled_value_numerator.is_negative()
        || expected_controlled_value_numerator.magnitude() > maximum_expected
    {
        return Err(ProtocolError::InvalidBondState);
    }
    if controlled_value_numerator_v2(
        trader_root,
        mark_price_atoms,
        global_funding_index_numerator,
        insurance_reserve_atoms,
        bounds,
    )? != expected_controlled_value_numerator
    {
        return Err(ProtocolError::ConservationViolation);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum NullifierKindV2 {
    Deposit,
    Withdrawal,
}

impl NullifierKindV2 {
    pub const fn code(self) -> u8 {
        match self {
            Self::Deposit => 1,
            Self::Withdrawal => 2,
        }
    }

    pub const fn domain(self) -> SparseStateDomainV2 {
        match self {
            Self::Deposit => SparseStateDomainV2::DepositNullifier,
            Self::Withdrawal => SparseStateDomainV2::WithdrawalNullifier,
        }
    }
}

impl CanonicalEncode for NullifierKindV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.code());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SparseNullifierUpdateV2 {
    pub kind: NullifierKindV2,
    pub nullifier: Hash32,
    pub path: SparseNullifierPathV2,
}

impl CanonicalEncode for SparseNullifierUpdateV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.kind.encode_to(out);
        out.extend_from_slice(&self.nullifier);
        self.path.encode_to(out);
    }
}

pub fn canonical_nullifier_update_batch_bytes_v2(
    updates: &[SparseNullifierUpdateV2],
) -> Result<Vec<u8>, ProtocolError> {
    if updates.len() > MAX_SPARSE_MERKLE_SUM_UPDATES_PER_BATCH_V2
        || updates.iter().any(|update| {
            update.path.kind != update.kind
                || update.path.siblings.len() != SPARSE_MERKLE_SUM_DEPTH_V2
        })
    {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    let mut bytes = Vec::new();
    put_u16(
        &mut bytes,
        u16::try_from(updates.len()).map_err(|_| ProtocolError::ArithmeticOverflow)?,
    );
    for update in updates {
        update.encode_to(&mut bytes);
    }
    if bytes.len() > MAX_SPARSE_NULLIFIER_UPDATE_BATCH_BYTES_V2 {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    Ok(bytes)
}

/// Compact sparse-set node.  Nullifier paths commit only cardinality; trader
/// collateral/cost/OI/funding aggregates cannot be smuggled into this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SparseNullifierNodeV2 {
    pub hash: Hash32,
    pub count: u128,
}

impl CanonicalEncode for SparseNullifierNodeV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.hash);
        out.extend_from_slice(&self.count.to_be_bytes());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SparseNullifierRootV2 {
    pub kind: NullifierKindV2,
    pub hash: Hash32,
    pub count: u128,
}

impl CanonicalEncode for SparseNullifierRootV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.kind.encode_to(out);
        out.extend_from_slice(&self.hash);
        out.extend_from_slice(&self.count.to_be_bytes());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SparseNullifierPathV2 {
    pub kind: NullifierKindV2,
    pub siblings: Vec<SparseNullifierNodeV2>,
}

impl CanonicalEncode for SparseNullifierPathV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.kind.encode_to(out);
        // As above, consensus callers validate the exact frozen depth first;
        // direct diagnostic encoding of malformed input must not panic.
        put_u16(out, u16::try_from(self.siblings.len()).unwrap_or(u16::MAX));
        for sibling in &self.siblings {
            sibling.encode_to(out);
        }
    }
}

fn empty_nullifier_leaf_hash_v2(kind: NullifierKindV2) -> Hash32 {
    tagged_hash(
        "ECX/incremental-nullifier-empty-leaf/v1",
        &[SPARSE_MERKLE_SUM_VERSION_V2, kind.code()],
    )
}

fn present_nullifier_leaf_hash_v2(kind: NullifierKindV2, nullifier: Hash32) -> Hash32 {
    let mut bytes = Vec::with_capacity(34);
    put_u8(&mut bytes, SPARSE_MERKLE_SUM_VERSION_V2);
    kind.encode_to(&mut bytes);
    bytes.extend_from_slice(&nullifier);
    tagged_hash("ECX/incremental-nullifier-present/v1", &bytes)
}

fn nullifier_parent_hash_v2(
    kind: NullifierKindV2,
    height: u16,
    left: SparseNullifierNodeV2,
    right: SparseNullifierNodeV2,
    count: u128,
) -> Hash32 {
    let mut bytes = Vec::with_capacity(3 + 2 * 48 + 16);
    put_u8(&mut bytes, SPARSE_MERKLE_SUM_VERSION_V2);
    kind.encode_to(&mut bytes);
    put_u16(&mut bytes, height);
    left.encode_to(&mut bytes);
    right.encode_to(&mut bytes);
    bytes.extend_from_slice(&count.to_be_bytes());
    tagged_hash("ECX/incremental-nullifier-parent/v1", &bytes)
}

pub fn canonical_empty_nullifier_node_v2(
    kind: NullifierKindV2,
    height: usize,
) -> Result<SparseNullifierNodeV2, ProtocolError> {
    if height > SPARSE_MERKLE_SUM_DEPTH_V2 {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    canonical_empty_nullifier_ladder_v2(kind)?
        .get(height)
        .copied()
        .ok_or(ProtocolError::InvalidMerkleProof)
}

/// Build every canonical empty node once. Reusing this bounded ladder is
/// consensus-equivalent to independently recomputing each height, while
/// avoiding quadratic SHA-256 work when validating a depth-256 path.
fn canonical_empty_nullifier_ladder_v2(
    kind: NullifierKindV2,
) -> Result<Vec<SparseNullifierNodeV2>, ProtocolError> {
    let mut node = SparseNullifierNodeV2 {
        hash: empty_nullifier_leaf_hash_v2(kind),
        count: 0,
    };
    let mut ladder = Vec::with_capacity(SPARSE_MERKLE_SUM_DEPTH_V2 + 1);
    ladder.push(node);
    for next_height in 1..=SPARSE_MERKLE_SUM_DEPTH_V2 {
        node = SparseNullifierNodeV2 {
            hash: nullifier_parent_hash_v2(
                kind,
                u16::try_from(next_height).map_err(|_| ProtocolError::ArithmeticOverflow)?,
                node,
                node,
                0,
            ),
            count: 0,
        };
        ladder.push(node);
    }
    Ok(ladder)
}

pub fn canonical_empty_nullifier_root_v2(kind: NullifierKindV2) -> SparseNullifierRootV2 {
    let node = canonical_empty_nullifier_node_v2(kind, SPARSE_MERKLE_SUM_DEPTH_V2)
        .expect("frozen nullifier depth fits u16");
    SparseNullifierRootV2 {
        kind,
        hash: node.hash,
        count: 0,
    }
}

pub fn canonical_empty_nullifier_path_v2(kind: NullifierKindV2) -> SparseNullifierPathV2 {
    let mut siblings =
        canonical_empty_nullifier_ladder_v2(kind).expect("frozen nullifier depth fits u16");
    siblings.truncate(SPARSE_MERKLE_SUM_DEPTH_V2);
    SparseNullifierPathV2 { kind, siblings }
}

fn validate_nullifier_node_against_empty_v2(
    height: usize,
    node: SparseNullifierNodeV2,
    empty: SparseNullifierNodeV2,
) -> Result<(), ProtocolError> {
    if node.count > MAX_REACHABLE_INCREMENTAL_LEAF_COUNT_V2 {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    if node.count == 0 {
        if node != empty {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
    } else {
        if node.hash == [0; 32] || node.hash == empty.hash {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        if height < 128 && node.count > (1u128 << height) {
            return Err(ProtocolError::InvalidMerkleProof);
        }
    }
    Ok(())
}

impl SparseNullifierRootV2 {
    pub fn validate(self) -> Result<(), ProtocolError> {
        let ladder = canonical_empty_nullifier_ladder_v2(self.kind)?;
        validate_nullifier_node_against_empty_v2(
            SPARSE_MERKLE_SUM_DEPTH_V2,
            SparseNullifierNodeV2 {
                hash: self.hash,
                count: self.count,
            },
            ladder[SPARSE_MERKLE_SUM_DEPTH_V2],
        )
    }
}

fn compute_nullifier_root_v2(
    kind: NullifierKindV2,
    nullifier: Hash32,
    present: bool,
    path: &SparseNullifierPathV2,
    empty_ladder: &[SparseNullifierNodeV2],
) -> Result<SparseNullifierRootV2, ProtocolError> {
    if nullifier == [0; 32]
        || path.kind != kind
        || path.siblings.len() != SPARSE_MERKLE_SUM_DEPTH_V2
        || empty_ladder.len() != SPARSE_MERKLE_SUM_DEPTH_V2 + 1
    {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    let mut current = SparseNullifierNodeV2 {
        hash: if present {
            present_nullifier_leaf_hash_v2(kind, nullifier)
        } else {
            empty_nullifier_leaf_hash_v2(kind)
        },
        count: u128::from(present),
    };
    for (level, sibling) in path.siblings.iter().copied().enumerate() {
        validate_nullifier_node_against_empty_v2(level, sibling, empty_ladder[level])?;
        let (left, right) = if key_bit_lsb_first(&nullifier, level) {
            (sibling, current)
        } else {
            (current, sibling)
        };
        let count = left
            .count
            .checked_add(right.count)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        current = SparseNullifierNodeV2 {
            hash: nullifier_parent_hash_v2(
                kind,
                u16::try_from(level + 1).map_err(|_| ProtocolError::ArithmeticOverflow)?,
                left,
                right,
                count,
            ),
            count,
        };
    }
    Ok(SparseNullifierRootV2 {
        kind,
        hash: current.hash,
        count: current.count,
    })
}

pub fn verify_sparse_nullifier_updates_v2(
    initial_root: SparseNullifierRootV2,
    updates: &[SparseNullifierUpdateV2],
    maximum_updates: usize,
) -> Result<SparseNullifierRootV2, ProtocolError> {
    let empty_ladder = canonical_empty_nullifier_ladder_v2(initial_root.kind)?;
    validate_nullifier_node_against_empty_v2(
        SPARSE_MERKLE_SUM_DEPTH_V2,
        SparseNullifierNodeV2 {
            hash: initial_root.hash,
            count: initial_root.count,
        },
        empty_ladder[SPARSE_MERKLE_SUM_DEPTH_V2],
    )?;
    if maximum_updates == 0
        || maximum_updates > MAX_SPARSE_MERKLE_SUM_UPDATES_PER_BATCH_V2
        || updates.len() > maximum_updates
    {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    if let Some(first) = updates.first() {
        if initial_root.kind != first.kind
            || updates.iter().any(|update| {
                update.kind != first.kind
                    || update.path.kind != update.kind
                    || update.path.siblings.len() != SPARSE_MERKLE_SUM_DEPTH_V2
            })
        {
            return Err(ProtocolError::InvalidMerkleProof);
        }
    }
    canonical_nullifier_update_batch_bytes_v2(updates)?;
    if updates.is_empty() {
        return Ok(initial_root);
    }
    let kind = updates[0].kind;
    let mut seen = BTreeSet::new();
    if updates.iter().any(|update| !seen.insert(update.nullifier)) {
        return Err(ProtocolError::DuplicateMerkleKey);
    }
    let mut root = initial_root;
    for update in updates {
        let old =
            compute_nullifier_root_v2(kind, update.nullifier, false, &update.path, &empty_ladder)?;
        if old != root {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        root =
            compute_nullifier_root_v2(kind, update.nullifier, true, &update.path, &empty_ladder)?;
    }
    validate_nullifier_node_against_empty_v2(
        SPARSE_MERKLE_SUM_DEPTH_V2,
        SparseNullifierNodeV2 {
            hash: root.hash,
            count: root.count,
        },
        empty_ladder[SPARSE_MERKLE_SUM_DEPTH_V2],
    )?;
    Ok(root)
}

// -------------------------------------------------------------------------
// Typed incremental order book and carried position-risk extrema.
// -------------------------------------------------------------------------

const ORDER_INDEX_VERSION_V2: u8 = 1;

/// Authenticated context needed to validate a confidential resting order.
/// The future successor configuration will freeze these values; keeping them
/// explicit prevents replay across a chain, market, or exchange singleton.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalOrderContextV2 {
    pub chain_id: Hash32,
    pub market: MarketId,
    pub configuration_hash: Hash32,
    pub risk_params: RiskParams,
    pub sidechain_height: u64,
}

impl IncrementalOrderContextV2 {
    pub fn validate(self) -> Result<(), ProtocolError> {
        if self.chain_id == [0; 32] || self.configuration_hash == [0; 32] {
            return Err(ProtocolError::InvalidBondState);
        }
        self.market.validate()?;
        self.risk_params.validate().map(|_| ())
    }
}

/// Exact price-time candidate carried by every order-index subtree root. Buy
/// candidates sort by descending price; sell candidates by ascending price.
/// Both then use ascending matcher receipt sequence and order id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OrderPriorityV2 {
    pub side: Side,
    pub limit_price_atoms: u64,
    pub received_sequence: u128,
    pub order_id: OrderId,
}

impl OrderPriorityV2 {
    fn validate(self) -> Result<(), ProtocolError> {
        if self.limit_price_atoms == 0 || self.order_id == [0; 32] {
            return Err(ProtocolError::InvalidBondState);
        }
        Ok(())
    }

    /// Shared ordering only; callers must separately authenticate membership
    /// and eligibility. Less means this candidate has higher priority.
    pub fn compare_priority(self, rhs: Self) -> Result<std::cmp::Ordering, ProtocolError> {
        self.validate()?;
        rhs.validate()?;
        if self.side != rhs.side {
            return Err(ProtocolError::InvalidBondState);
        }
        let price = match self.side {
            Side::Buy => rhs.limit_price_atoms.cmp(&self.limit_price_atoms),
            Side::Sell => self.limit_price_atoms.cmp(&rhs.limit_price_atoms),
        };
        Ok(price
            .then_with(|| self.received_sequence.cmp(&rhs.received_sequence))
            .then_with(|| self.order_id.cmp(&rhs.order_id)))
    }

    fn better(self, rhs: Self) -> Result<Self, ProtocolError> {
        Ok(if self.compare_priority(rhs)?.is_le() {
            self
        } else {
            rhs
        })
    }
}

impl CanonicalEncode for OrderPriorityV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.side as u8);
        put_u64(out, self.limit_price_atoms);
        out.extend_from_slice(&self.received_sequence.to_be_bytes());
        out.extend_from_slice(&self.order_id);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OrderExpiryV2 {
    pub expires_at_height: u64,
    pub order_id: OrderId,
}

impl CanonicalEncode for OrderExpiryV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u64(out, self.expires_at_height);
        out.extend_from_slice(&self.order_id);
    }
}

/// Root-carried order-book state. Best candidates authenticate exact FIFO
/// priority without a scan, while selected-margin extrema replace the finite
/// relation's separate active-order-risk vector root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OrderIndexAggregateV2 {
    pub leaf_count: u128,
    pub total_remaining_quantity_atoms: Uint256V2,
    pub best_buy: Option<OrderPriorityV2>,
    pub best_sell: Option<OrderPriorityV2>,
    pub earliest_expiry: Option<OrderExpiryV2>,
    pub minimum_selected_initial_margin_bps: u32,
    pub maximum_selected_initial_margin_bps: u32,
}

impl OrderIndexAggregateV2 {
    pub const ZERO: Self = Self {
        leaf_count: 0,
        total_remaining_quantity_atoms: Uint256V2::ZERO,
        best_buy: None,
        best_sell: None,
        earliest_expiry: None,
        minimum_selected_initial_margin_bps: 0,
        maximum_selected_initial_margin_bps: 0,
    };

    pub fn is_zero(self) -> bool {
        self == Self::ZERO
    }

    fn choose_priority(
        left: Option<OrderPriorityV2>,
        right: Option<OrderPriorityV2>,
    ) -> Result<Option<OrderPriorityV2>, ProtocolError> {
        match (left, right) {
            (None, value) | (value, None) => Ok(value),
            (Some(left), Some(right)) => Ok(Some(left.better(right)?)),
        }
    }

    fn choose_expiry(
        left: Option<OrderExpiryV2>,
        right: Option<OrderExpiryV2>,
    ) -> Option<OrderExpiryV2> {
        match (left, right) {
            (None, value) | (value, None) => value,
            (Some(left), Some(right)) => Some(
                if (left.expires_at_height, left.order_id)
                    <= (right.expires_at_height, right.order_id)
                {
                    left
                } else {
                    right
                },
            ),
        }
    }

    pub fn checked_add(self, rhs: Self) -> Result<Self, ProtocolError> {
        let minimum = match (
            self.minimum_selected_initial_margin_bps,
            rhs.minimum_selected_initial_margin_bps,
        ) {
            (0, value) | (value, 0) => value,
            (left, right) => left.min(right),
        };
        Ok(Self {
            leaf_count: self
                .leaf_count
                .checked_add(rhs.leaf_count)
                .ok_or(ProtocolError::ArithmeticOverflow)?,
            total_remaining_quantity_atoms: self
                .total_remaining_quantity_atoms
                .checked_add(rhs.total_remaining_quantity_atoms)?,
            best_buy: Self::choose_priority(self.best_buy, rhs.best_buy)?,
            best_sell: Self::choose_priority(self.best_sell, rhs.best_sell)?,
            earliest_expiry: Self::choose_expiry(self.earliest_expiry, rhs.earliest_expiry),
            minimum_selected_initial_margin_bps: minimum,
            maximum_selected_initial_margin_bps: self
                .maximum_selected_initial_margin_bps
                .max(rhs.maximum_selected_initial_margin_bps),
        })
    }

    pub fn validate(self) -> Result<(), ProtocolError> {
        if self.leaf_count == 0 {
            return if self.is_zero() {
                Ok(())
            } else {
                Err(ProtocolError::InvalidBondState)
            };
        }
        if self.leaf_count > MAX_REACHABLE_INCREMENTAL_LEAF_COUNT_V2
            || self.total_remaining_quantity_atoms.is_zero()
            || self.earliest_expiry.is_none()
            || (self.best_buy.is_none() && self.best_sell.is_none())
            || !ALLOWED_INITIAL_MARGIN_BPS_V2.contains(&self.minimum_selected_initial_margin_bps)
            || !ALLOWED_INITIAL_MARGIN_BPS_V2.contains(&self.maximum_selected_initial_margin_bps)
            || self.minimum_selected_initial_margin_bps > self.maximum_selected_initial_margin_bps
        {
            return Err(ProtocolError::InvalidBondState);
        }
        let maximum_quantity = Uint256V2::from_u128(self.leaf_count).checked_mul_u64(u64::MAX)?;
        if self.total_remaining_quantity_atoms > maximum_quantity
            || self.best_buy.is_some_and(|candidate| {
                candidate.side != Side::Buy || candidate.validate().is_err()
            })
            || self.best_sell.is_some_and(|candidate| {
                candidate.side != Side::Sell || candidate.validate().is_err()
            })
        {
            return Err(ProtocolError::InvalidBondState);
        }
        Ok(())
    }
}

fn encode_order_priority_option_v2(value: Option<OrderPriorityV2>, out: &mut Vec<u8>) {
    match value {
        None => put_u8(out, 0),
        Some(value) => {
            put_u8(out, 1);
            value.encode_to(out);
        }
    }
}

impl CanonicalEncode for OrderIndexAggregateV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.leaf_count.to_be_bytes());
        self.total_remaining_quantity_atoms.encode_to(out);
        encode_order_priority_option_v2(self.best_buy, out);
        encode_order_priority_option_v2(self.best_sell, out);
        match self.earliest_expiry {
            None => put_u8(out, 0),
            Some(expiry) => {
                put_u8(out, 1);
                expiry.encode_to(out);
            }
        }
        put_u32(out, self.minimum_selected_initial_margin_bps);
        put_u32(out, self.maximum_selected_initial_margin_bps);
    }
}

/// Confidential authenticated resting-order leaf. The signed order and signed
/// selected leverage are opened together, eliminating the finite relation's
/// parallel `open_orders` and `active_order_risk` vectors. The admission hash
/// and sequence are later linked to the exact matcher receipt by the successor
/// relation; neither is trusted as an unauthenticated timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OrderIndexLeafV2 {
    pub version: u8,
    pub signed_order: SuccessorSignedLimitOrderV2,
    pub risk: OrderRiskCommitmentV2,
    pub remaining_quantity_atoms: u64,
    pub received_sequence: u128,
    pub admission_receipt_hash: Hash32,
    pub trader_order_generation: u128,
    pub salt: Hash32,
}

impl OrderIndexLeafV2 {
    pub const VERSION: u8 = 1;

    pub fn order_id(&self) -> OrderId {
        self.signed_order.order_id()
    }

    pub fn validate(&self, context: IncrementalOrderContextV2) -> Result<(), ProtocolError> {
        context.validate()?;
        self.signed_order.verify()?;
        self.risk.verify(context.risk_params)?;
        let order = &self.signed_order.order;
        if self.version != Self::VERSION
            || self.salt == [0; 32]
            || self.admission_receipt_hash == [0; 32]
            || order.chain_id != context.chain_id
            || order.market != context.market
            || order.time_in_force != TimeInForce::GoodTilHeight
            || self.remaining_quantity_atoms == 0
            || self.remaining_quantity_atoms > order.quantity.get()
            || self.risk.configuration_hash != context.configuration_hash
            || self.risk.order_id != self.order_id()
            || self.risk.trader != order.trader
        {
            return Err(ProtocolError::InvalidBondState);
        }
        Ok(())
    }

    pub fn validate_against_trader(
        &self,
        trader: &TraderLeafV2,
        context: IncrementalOrderContextV2,
        bounds: IncrementalAccountingBoundsV2,
        require_current_generation: bool,
    ) -> Result<(), ProtocolError> {
        self.validate(context)?;
        trader.validate(bounds)?;
        if trader.trader != self.signed_order.order.trader
            || (require_current_generation
                && trader.order_generation != self.trader_order_generation)
        {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        Ok(())
    }

    pub fn priority(&self) -> OrderPriorityV2 {
        OrderPriorityV2 {
            side: self.signed_order.order.side,
            limit_price_atoms: self.signed_order.order.limit_price.get(),
            received_sequence: self.received_sequence,
            order_id: self.order_id(),
        }
    }

    pub fn aggregate(
        &self,
        context: IncrementalOrderContextV2,
    ) -> Result<OrderIndexAggregateV2, ProtocolError> {
        self.validate(context)?;
        let priority = self.priority();
        let aggregate = OrderIndexAggregateV2 {
            leaf_count: 1,
            total_remaining_quantity_atoms: Uint256V2::from_u64(self.remaining_quantity_atoms),
            best_buy: (priority.side == Side::Buy).then_some(priority),
            best_sell: (priority.side == Side::Sell).then_some(priority),
            earliest_expiry: Some(OrderExpiryV2 {
                expires_at_height: self.signed_order.order.expires_at_height,
                order_id: self.order_id(),
            }),
            minimum_selected_initial_margin_bps: self.risk.selected_initial_margin_bps,
            maximum_selected_initial_margin_bps: self.risk.selected_initial_margin_bps,
        };
        aggregate.validate()?;
        Ok(aggregate)
    }

    fn commitment(&self, context: IncrementalOrderContextV2) -> Result<Hash32, ProtocolError> {
        self.validate(context)?;
        Ok(canonical_hash("ECX/incremental-order-index-leaf/v1", self))
    }

    fn immutable_terms_equal(&self, next: &Self) -> bool {
        self.version == next.version
            && self.signed_order == next.signed_order
            && self.risk == next.risk
            && self.received_sequence == next.received_sequence
            && self.admission_receipt_hash == next.admission_receipt_hash
            && self.trader_order_generation == next.trader_order_generation
    }

    pub fn is_live_and_current(&self, trader: &TraderLeafV2, height: u64) -> bool {
        self.signed_order.order.is_live_at(height)
            && self.trader_order_generation == trader.order_generation
    }
}

impl CanonicalEncode for OrderIndexLeafV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        self.signed_order.encode_to(out);
        self.risk.encode_to(out);
        put_u64(out, self.remaining_quantity_atoms);
        out.extend_from_slice(&self.received_sequence.to_be_bytes());
        out.extend_from_slice(&self.admission_receipt_hash);
        out.extend_from_slice(&self.trader_order_generation.to_be_bytes());
        out.extend_from_slice(&self.salt);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum OrderIndexOperationKindV2 {
    Insert,
    PartialFill,
    RemoveFilled,
    RemoveCancelled,
    RemovePruned,
    /// Authenticated nonmembership at the exact cancellation point. This is
    /// a semantic no-op only when a signed cancellation is separately bound
    /// by the recursive order/account children.
    ConfirmAbsentCancelled,
}

impl OrderIndexOperationKindV2 {
    const fn code(self) -> u8 {
        match self {
            Self::Insert => 1,
            Self::PartialFill => 2,
            Self::RemoveFilled => 3,
            Self::RemoveCancelled => 4,
            Self::RemovePruned => 5,
            Self::ConfirmAbsentCancelled => 6,
        }
    }
}

impl CanonicalEncode for OrderIndexOperationKindV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.code());
    }
}

/// One logical order operation in exact matcher-command execution order. The
/// sparse frontier later coalesces all operations on one id, but this chain is
/// retained so insert/fill/cancel/prune semantics cannot be replaced by an
/// arbitrary old/new leaf pair.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OrderIndexOperationV2 {
    pub kind: OrderIndexOperationKindV2,
    pub order_id: OrderId,
    pub old_leaf: Option<OrderIndexLeafV2>,
    pub new_leaf: Option<OrderIndexLeafV2>,
    pub trader_leaf: TraderLeafV2,
    pub filled_quantity_atoms: u64,
}

impl OrderIndexOperationV2 {
    fn validate(
        &self,
        context: IncrementalOrderContextV2,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<(), ProtocolError> {
        self.trader_leaf.validate(bounds)?;
        for leaf in self.old_leaf.iter().chain(self.new_leaf.iter()) {
            if leaf.order_id() != self.order_id {
                return Err(ProtocolError::InvalidMerkleProof);
            }
            leaf.validate_against_trader(&self.trader_leaf, context, bounds, false)?;
        }
        match self.kind {
            OrderIndexOperationKindV2::Insert => {
                let next = self
                    .new_leaf
                    .as_ref()
                    .filter(|_| self.old_leaf.is_none() && self.filled_quantity_atoms == 0)
                    .ok_or(ProtocolError::InvalidMerkleProof)?;
                next.validate_against_trader(&self.trader_leaf, context, bounds, true)?;
                if next.remaining_quantity_atoms != next.signed_order.order.quantity.get()
                    || !next.signed_order.order.is_live_at(context.sidechain_height)
                {
                    return Err(ProtocolError::InvalidMerkleProof);
                }
            }
            OrderIndexOperationKindV2::PartialFill => {
                let (old, next) = self
                    .old_leaf
                    .as_ref()
                    .zip(self.new_leaf.as_ref())
                    .ok_or(ProtocolError::InvalidMerkleProof)?;
                if self.filled_quantity_atoms == 0
                    || !old.immutable_terms_equal(next)
                    || !old.is_live_and_current(&self.trader_leaf, context.sidechain_height)
                    || old
                        .remaining_quantity_atoms
                        .checked_sub(self.filled_quantity_atoms)
                        != Some(next.remaining_quantity_atoms)
                    || next.remaining_quantity_atoms == 0
                {
                    return Err(ProtocolError::InvalidMerkleProof);
                }
            }
            OrderIndexOperationKindV2::RemoveFilled => {
                let old = self
                    .old_leaf
                    .as_ref()
                    .filter(|_| self.new_leaf.is_none())
                    .ok_or(ProtocolError::InvalidMerkleProof)?;
                if self.filled_quantity_atoms == 0
                    || !old.is_live_and_current(&self.trader_leaf, context.sidechain_height)
                    || old.remaining_quantity_atoms != self.filled_quantity_atoms
                {
                    return Err(ProtocolError::InvalidMerkleProof);
                }
            }
            OrderIndexOperationKindV2::RemoveCancelled => {
                if self.old_leaf.is_none()
                    || self.new_leaf.is_some()
                    || self.filled_quantity_atoms != 0
                {
                    return Err(ProtocolError::InvalidMerkleProof);
                }
            }
            OrderIndexOperationKindV2::RemovePruned => {
                let old = self
                    .old_leaf
                    .as_ref()
                    .filter(|_| self.new_leaf.is_none() && self.filled_quantity_atoms == 0)
                    .ok_or(ProtocolError::InvalidMerkleProof)?;
                if old.signed_order.order.expires_at_height >= context.sidechain_height
                    && old.trader_order_generation >= self.trader_leaf.order_generation
                {
                    return Err(ProtocolError::InvalidMerkleProof);
                }
                if old.trader_order_generation > self.trader_leaf.order_generation {
                    return Err(ProtocolError::InvalidMerkleProof);
                }
            }
            OrderIndexOperationKindV2::ConfirmAbsentCancelled => {
                if self.old_leaf.is_some()
                    || self.new_leaf.is_some()
                    || self.filled_quantity_atoms != 0
                {
                    return Err(ProtocolError::InvalidMerkleProof);
                }
            }
        }
        Ok(())
    }
}

impl CanonicalEncode for OrderIndexOperationV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.kind.encode_to(out);
        out.extend_from_slice(&self.order_id);
        match &self.old_leaf {
            None => put_u8(out, 0),
            Some(leaf) => {
                put_u8(out, 1);
                leaf.encode_to(out);
            }
        }
        match &self.new_leaf {
            None => put_u8(out, 0),
            Some(leaf) => {
                put_u8(out, 1);
                leaf.encode_to(out);
            }
        }
        self.trader_leaf.encode_to(out);
        put_u64(out, self.filled_quantity_atoms);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OrderIndexNodeV2 {
    pub hash: Hash32,
    pub aggregate: OrderIndexAggregateV2,
}

impl CanonicalEncode for OrderIndexNodeV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.hash);
        self.aggregate.encode_to(out);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OrderIndexRootV2 {
    pub hash: Hash32,
    pub aggregate: OrderIndexAggregateV2,
}

impl CanonicalEncode for OrderIndexRootV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.hash);
        self.aggregate.encode_to(out);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[allow(clippy::large_enum_variant)]
pub enum OrderIndexFrontierItemV2 {
    CanonicalEmpty,
    Occupied(OrderIndexNodeV2),
}

impl CanonicalEncode for OrderIndexFrontierItemV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        match self {
            Self::CanonicalEmpty => put_u8(out, 0),
            Self::Occupied(node) => {
                put_u8(out, 1);
                node.encode_to(out);
            }
        }
    }
}

fn order_index_empty_leaf_v2() -> OrderIndexNodeV2 {
    #[derive(Clone, Copy)]
    struct Empty;
    impl CanonicalEncode for Empty {
        fn encode_to(&self, out: &mut Vec<u8>) {
            put_u8(out, 0);
        }
    }
    OrderIndexNodeV2 {
        hash: canonical_hash("ECX/incremental-order-index-empty-leaf/v1", &Empty),
        aggregate: OrderIndexAggregateV2::ZERO,
    }
}

fn order_index_parent_node_v2(
    height: u16,
    left: OrderIndexNodeV2,
    right: OrderIndexNodeV2,
) -> Result<OrderIndexNodeV2, ProtocolError> {
    let aggregate = left.aggregate.checked_add(right.aggregate)?;
    aggregate.validate()?;
    #[derive(Clone, Copy)]
    struct Parent {
        height: u16,
        left: OrderIndexNodeV2,
        right: OrderIndexNodeV2,
        aggregate: OrderIndexAggregateV2,
    }
    impl CanonicalEncode for Parent {
        fn encode_to(&self, out: &mut Vec<u8>) {
            put_u16(out, self.height);
            self.left.encode_to(out);
            self.right.encode_to(out);
            self.aggregate.encode_to(out);
        }
    }
    Ok(OrderIndexNodeV2 {
        hash: canonical_hash(
            "ECX/incremental-order-index-parent/v1",
            &Parent {
                height,
                left,
                right,
                aggregate,
            },
        ),
        aggregate,
    })
}

fn canonical_empty_order_index_nodes_v2() -> Result<Vec<OrderIndexNodeV2>, ProtocolError> {
    let mut nodes = Vec::with_capacity(SPARSE_MERKLE_SUM_DEPTH_V2 + 1);
    nodes.push(order_index_empty_leaf_v2());
    for height in 1..=SPARSE_MERKLE_SUM_DEPTH_V2 {
        let child = nodes[height - 1];
        nodes.push(order_index_parent_node_v2(
            u16::try_from(height).map_err(|_| ProtocolError::ArithmeticOverflow)?,
            child,
            child,
        )?);
    }
    Ok(nodes)
}

pub fn canonical_empty_order_index_root_v2() -> OrderIndexRootV2 {
    let node = canonical_empty_order_index_nodes_v2().expect("fixed-depth order empty tree")
        [SPARSE_MERKLE_SUM_DEPTH_V2];
    OrderIndexRootV2 {
        hash: node.hash,
        aggregate: node.aggregate,
    }
}

fn order_index_leaf_node_v2(
    leaf: &OrderIndexLeafV2,
    context: IncrementalOrderContextV2,
) -> Result<OrderIndexNodeV2, ProtocolError> {
    let aggregate = leaf.aggregate(context)?;
    #[derive(Clone, Copy)]
    struct Preimage {
        commitment: Hash32,
        aggregate: OrderIndexAggregateV2,
    }
    impl CanonicalEncode for Preimage {
        fn encode_to(&self, out: &mut Vec<u8>) {
            out.extend_from_slice(&self.commitment);
            self.aggregate.encode_to(out);
        }
    }
    Ok(OrderIndexNodeV2 {
        hash: canonical_hash(
            "ECX/incremental-order-index-present-leaf/v1",
            &Preimage {
                commitment: leaf.commitment(context)?,
                aggregate,
            },
        ),
        aggregate,
    })
}

fn order_index_frontier_node_v2(
    item: OrderIndexFrontierItemV2,
    subtree_height: usize,
    empties: &[OrderIndexNodeV2],
) -> Result<OrderIndexNodeV2, ProtocolError> {
    let empty = *empties
        .get(subtree_height)
        .ok_or(ProtocolError::InvalidMerkleProof)?;
    match item {
        OrderIndexFrontierItemV2::CanonicalEmpty => Ok(empty),
        OrderIndexFrontierItemV2::Occupied(node) => {
            node.aggregate.validate()?;
            if node.aggregate.is_zero() || node == empty {
                return Err(ProtocolError::NonCanonicalEncoding);
            }
            Ok(node)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OrderIndexBatchProofV2 {
    pub operations: Vec<OrderIndexOperationV2>,
    pub frontier: Vec<OrderIndexFrontierItemV2>,
}

impl CanonicalEncode for OrderIndexBatchProofV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, ORDER_INDEX_VERSION_V2);
        put_u16(
            out,
            u16::try_from(self.operations.len()).unwrap_or(u16::MAX),
        );
        for operation in &self.operations {
            operation.encode_to(out);
        }
        put_u16(out, u16::try_from(self.frontier.len()).unwrap_or(u16::MAX));
        for item in &self.frontier {
            item.encode_to(out);
        }
    }
}

#[derive(Debug, Clone)]
struct DerivedOrderIndexReplacementV2 {
    order_id: OrderId,
    old_leaf: Option<OrderIndexLeafV2>,
    new_leaf: Option<OrderIndexLeafV2>,
}

fn derive_order_index_replacements_v2(
    operations: &[OrderIndexOperationV2],
    context: IncrementalOrderContextV2,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<Vec<DerivedOrderIndexReplacementV2>, ProtocolError> {
    if operations.is_empty() || operations.len() > MAX_ORDER_INDEX_OPERATIONS_PER_BATCH_V2 {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    for operation in operations {
        operation.validate(context, bounds)?;
    }
    let mut ids = operations
        .iter()
        .map(|operation| operation.order_id)
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    if ids.len() > MAX_ORDER_INDEX_UNIQUE_KEYS_PER_BATCH_V2 {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    let mut replacements = Vec::with_capacity(ids.len());
    for order_id in ids {
        let chain = operations
            .iter()
            .filter(|operation| operation.order_id == order_id)
            .collect::<Vec<_>>();
        for pair in chain.windows(2) {
            if pair[0].new_leaf != pair[1].old_leaf {
                return Err(ProtocolError::InvalidMerkleProof);
            }
        }
        let old_leaf = chain
            .first()
            .and_then(|operation| operation.old_leaf.clone());
        let new_leaf = chain
            .last()
            .and_then(|operation| operation.new_leaf.clone());
        if old_leaf == new_leaf {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        replacements.push(DerivedOrderIndexReplacementV2 {
            order_id,
            old_leaf,
            new_leaf,
        });
    }
    Ok(replacements)
}

fn order_frontier_slot_count_v2(
    replacements: &[DerivedOrderIndexReplacementV2],
) -> Result<usize, ProtocolError> {
    let mut frames = vec![(0usize, 0usize, replacements.len())];
    let mut slots = 0usize;
    while let Some((depth, lo, hi)) = frames.pop() {
        if depth > SPARSE_MERKLE_SUM_DEPTH_V2 || lo > hi || hi > replacements.len() {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        if lo == hi {
            slots = slots
                .checked_add(1)
                .ok_or(ProtocolError::ArithmeticOverflow)?;
        } else if depth == SPARSE_MERKLE_SUM_DEPTH_V2 {
            if hi - lo != 1 {
                return Err(ProtocolError::DuplicateMerkleKey);
            }
        } else {
            let split = replacements[lo..hi]
                .partition_point(|replacement| !root_bit_msb_first(&replacement.order_id, depth));
            let split = lo + split;
            frames.push((depth + 1, split, hi));
            frames.push((depth + 1, lo, split));
        }
    }
    if slots > MAX_ORDER_INDEX_SHARED_FRONTIER_ITEMS_V2 {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    Ok(slots)
}

fn compute_order_index_batch_v2(
    replacements: &[DerivedOrderIndexReplacementV2],
    frontier: &[OrderIndexFrontierItemV2],
    context: IncrementalOrderContextV2,
) -> Result<(OrderIndexNodeV2, OrderIndexNodeV2), ProtocolError> {
    #[derive(Clone, Copy)]
    enum Frame {
        Visit { depth: usize, lo: usize, hi: usize },
        Combine { depth: usize },
    }
    let empties = canonical_empty_order_index_nodes_v2()?;
    let mut frames = vec![Frame::Visit {
        depth: 0,
        lo: 0,
        hi: replacements.len(),
    }];
    let mut results = Vec::new();
    let mut frontier_cursor = 0usize;
    while let Some(frame) = frames.pop() {
        match frame {
            Frame::Visit { depth, lo, hi } => {
                if lo == hi {
                    let item = *frontier
                        .get(frontier_cursor)
                        .ok_or(ProtocolError::UnexpectedEnd)?;
                    frontier_cursor += 1;
                    let node = order_index_frontier_node_v2(
                        item,
                        SPARSE_MERKLE_SUM_DEPTH_V2 - depth,
                        &empties,
                    )?;
                    results.push((node, node));
                } else if depth == SPARSE_MERKLE_SUM_DEPTH_V2 {
                    if hi - lo != 1 {
                        return Err(ProtocolError::DuplicateMerkleKey);
                    }
                    let replacement = &replacements[lo];
                    let old = match &replacement.old_leaf {
                        Some(leaf) => order_index_leaf_node_v2(leaf, context)?,
                        None => empties[0],
                    };
                    let new = match &replacement.new_leaf {
                        Some(leaf) => order_index_leaf_node_v2(leaf, context)?,
                        None => empties[0],
                    };
                    results.push((old, new));
                } else {
                    let split = replacements[lo..hi].partition_point(|replacement| {
                        !root_bit_msb_first(&replacement.order_id, depth)
                    });
                    let split = lo + split;
                    frames.push(Frame::Combine { depth });
                    frames.push(Frame::Visit {
                        depth: depth + 1,
                        lo: split,
                        hi,
                    });
                    frames.push(Frame::Visit {
                        depth: depth + 1,
                        lo,
                        hi: split,
                    });
                }
            }
            Frame::Combine { depth } => {
                let (old_right, new_right) =
                    results.pop().ok_or(ProtocolError::InvalidMerkleProof)?;
                let (old_left, new_left) =
                    results.pop().ok_or(ProtocolError::InvalidMerkleProof)?;
                let height = u16::try_from(SPARSE_MERKLE_SUM_DEPTH_V2 - depth)
                    .map_err(|_| ProtocolError::ArithmeticOverflow)?;
                results.push((
                    order_index_parent_node_v2(height, old_left, old_right)?,
                    order_index_parent_node_v2(height, new_left, new_right)?,
                ));
            }
        }
    }
    if frontier_cursor != frontier.len() || results.len() != 1 {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    results.pop().ok_or(ProtocolError::InvalidMerkleProof)
}

impl OrderIndexBatchProofV2 {
    pub fn for_canonical_empty_root(
        operations: Vec<OrderIndexOperationV2>,
        context: IncrementalOrderContextV2,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<Self, ProtocolError> {
        let replacements = derive_order_index_replacements_v2(&operations, context, bounds)?;
        if replacements
            .iter()
            .any(|replacement| replacement.old_leaf.is_some())
        {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        let slots = order_frontier_slot_count_v2(&replacements)?;
        let proof = Self {
            operations,
            frontier: vec![OrderIndexFrontierItemV2::CanonicalEmpty; slots],
        };
        proof.canonical_bytes_checked(context, bounds)?;
        Ok(proof)
    }

    pub fn canonical_bytes_checked(
        &self,
        context: IncrementalOrderContextV2,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<Vec<u8>, ProtocolError> {
        let replacements = derive_order_index_replacements_v2(&self.operations, context, bounds)?;
        if self.frontier.len() != order_frontier_slot_count_v2(&replacements)?
            || self.frontier.len() > MAX_ORDER_INDEX_SHARED_FRONTIER_ITEMS_V2
        {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        for item in &self.frontier {
            if let OrderIndexFrontierItemV2::Occupied(node) = item {
                node.aggregate.validate()?;
                if node.aggregate.is_zero() {
                    return Err(ProtocolError::NonCanonicalEncoding);
                }
            }
        }
        let bytes = self.canonical_bytes();
        if bytes.len() > MAX_ORDER_INDEX_UPDATE_BATCH_BYTES_V2 {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        Ok(bytes)
    }

    pub fn verify(
        &self,
        expected_old_root: OrderIndexRootV2,
        context: IncrementalOrderContextV2,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<OrderIndexRootV2, ProtocolError> {
        expected_old_root.aggregate.validate()?;
        self.canonical_bytes_checked(context, bounds)?;
        let replacements = derive_order_index_replacements_v2(&self.operations, context, bounds)?;
        let (old, new) = compute_order_index_batch_v2(&replacements, &self.frontier, context)?;
        if old.hash != expected_old_root.hash || old.aggregate != expected_old_root.aggregate {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        new.aggregate.validate()?;
        Ok(OrderIndexRootV2 {
            hash: new.hash,
            aggregate: new.aggregate,
        })
    }
}

/// One immediate-root order action proof. Sibling zero is adjacent to the
/// leaf. Canonical empty subtrees use one byte; occupied siblings carry the
/// exact subtree aggregate. Fill and prune operations must open the best
/// price-time leaf committed by the predecessor root.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ChainedOrderIndexActionV2 {
    pub operation: OrderIndexOperationV2,
    pub siblings_leaf_to_root: Vec<OrderIndexFrontierItemV2>,
}

impl CanonicalEncode for ChainedOrderIndexActionV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.operation.encode_to(out);
        put_u16(
            out,
            u16::try_from(self.siblings_leaf_to_root.len()).unwrap_or(u16::MAX),
        );
        for sibling in &self.siblings_leaf_to_root {
            sibling.encode_to(out);
        }
    }
}

impl ChainedOrderIndexActionV2 {
    fn verify_apply(
        &self,
        expected_old_root: OrderIndexRootV2,
        context: IncrementalOrderContextV2,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<OrderIndexRootV2, ProtocolError> {
        self.operation.validate(context, bounds)?;
        expected_old_root.aggregate.validate()?;
        if self.siblings_leaf_to_root.len() != SPARSE_MERKLE_SUM_DEPTH_V2 {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        let empties = canonical_empty_order_index_nodes_v2()?;
        let mut old = match &self.operation.old_leaf {
            Some(leaf) => order_index_leaf_node_v2(leaf, context)?,
            None => empties[0],
        };
        let mut new = match &self.operation.new_leaf {
            Some(leaf) => order_index_leaf_node_v2(leaf, context)?,
            None => empties[0],
        };
        for (level, item) in self.siblings_leaf_to_root.iter().copied().enumerate() {
            let sibling = order_index_frontier_node_v2(item, level, &empties)?;
            let depth = SPARSE_MERKLE_SUM_DEPTH_V2 - 1 - level;
            let height = u16::try_from(level + 1).map_err(|_| ProtocolError::ArithmeticOverflow)?;
            if root_bit_msb_first(&self.operation.order_id, depth) {
                old = order_index_parent_node_v2(height, sibling, old)?;
                new = order_index_parent_node_v2(height, sibling, new)?;
            } else {
                old = order_index_parent_node_v2(height, old, sibling)?;
                new = order_index_parent_node_v2(height, new, sibling)?;
            }
        }
        if old.hash != expected_old_root.hash || old.aggregate != expected_old_root.aggregate {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        let requires_best = matches!(
            self.operation.kind,
            OrderIndexOperationKindV2::PartialFill
                | OrderIndexOperationKindV2::RemoveFilled
                | OrderIndexOperationKindV2::RemovePruned
        );
        if requires_best {
            let old_leaf = self
                .operation
                .old_leaf
                .as_ref()
                .ok_or(ProtocolError::InvalidMerkleProof)?;
            let expected_best = match old_leaf.signed_order.order.side {
                Side::Buy => expected_old_root.aggregate.best_buy,
                Side::Sell => expected_old_root.aggregate.best_sell,
            };
            if expected_best != Some(old_leaf.priority()) {
                return Err(ProtocolError::PriceTimePriorityViolation);
            }
        }
        Ok(OrderIndexRootV2 {
            hash: new.hash,
            aggregate: new.aggregate,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ChainedOrderIndexTranscriptV2 {
    pub actions: Vec<ChainedOrderIndexActionV2>,
}

impl CanonicalEncode for ChainedOrderIndexTranscriptV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u16(out, u16::try_from(self.actions.len()).unwrap_or(u16::MAX));
        for action in &self.actions {
            action.encode_to(out);
        }
    }
}

impl ChainedOrderIndexTranscriptV2 {
    pub fn canonical_bytes_checked(
        &self,
        context: IncrementalOrderContextV2,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<Vec<u8>, ProtocolError> {
        if self.actions.is_empty() || self.actions.len() > MAX_ORDER_INDEX_OPERATIONS_PER_BATCH_V2 {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        for action in &self.actions {
            action.operation.validate(context, bounds)?;
            if action.siblings_leaf_to_root.len() != SPARSE_MERKLE_SUM_DEPTH_V2 {
                return Err(ProtocolError::InvalidMerkleProof);
            }
            for item in &action.siblings_leaf_to_root {
                if let OrderIndexFrontierItemV2::Occupied(node) = item {
                    node.aggregate.validate()?;
                    if node.aggregate.is_zero() {
                        return Err(ProtocolError::NonCanonicalEncoding);
                    }
                }
            }
        }
        let bytes = self.canonical_bytes();
        if bytes.len() > MAX_CHAINED_ORDER_INDEX_TRANSCRIPT_BYTES_V2 {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        Ok(bytes)
    }

    pub fn verify(
        &self,
        initial_root: OrderIndexRootV2,
        context: IncrementalOrderContextV2,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<OrderIndexRootV2, ProtocolError> {
        Ok(self
            .verify_with_predecessor_roots(initial_root, context, bounds)?
            .0)
    }

    /// Verify the complete immediate-root transcript and return the exact
    /// authenticated predecessor root for every action. Consumers such as
    /// liquidation selection must use the root at their action index rather
    /// than the batch's initial or final aggregate.
    pub fn verify_with_predecessor_roots(
        &self,
        initial_root: OrderIndexRootV2,
        context: IncrementalOrderContextV2,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<(OrderIndexRootV2, Vec<OrderIndexRootV2>), ProtocolError> {
        self.canonical_bytes_checked(context, bounds)?;
        let mut root = initial_root;
        let mut predecessors = Vec::with_capacity(self.actions.len());
        for action in &self.actions {
            predecessors.push(root);
            root = action.verify_apply(root, context, bounds)?;
        }
        Ok((root, predecessors))
    }
}

/// Check the cross-side execution relation against the exact root-carried best
/// maker. This must be called at the immediate predecessor root of the fill.
pub fn verify_best_crossing_maker_v2(
    root: OrderIndexRootV2,
    maker: &OrderIndexLeafV2,
    taker_side: Side,
    taker_limit_price_atoms: u64,
    taker_received_sequence: u128,
) -> Result<(), ProtocolError> {
    root.aggregate.validate()?;
    let expected = match maker.signed_order.order.side {
        Side::Buy => root.aggregate.best_buy,
        Side::Sell => root.aggregate.best_sell,
    };
    if maker.signed_order.order.side == taker_side
        || expected != Some(maker.priority())
        || maker.received_sequence >= taker_received_sequence
    {
        return Err(ProtocolError::PriceTimePriorityViolation);
    }
    let crosses = match taker_side {
        Side::Buy => maker.signed_order.order.limit_price.get() <= taker_limit_price_atoms,
        Side::Sell => maker.signed_order.order.limit_price.get() >= taker_limit_price_atoms,
    };
    if !crosses {
        return Err(ProtocolError::PriceTimePriorityViolation);
    }
    Ok(())
}

/// Prove that the authenticated opposite-side head does not cross an IOC.
/// Because the aggregate commits the exact price-time head, a non-crossing
/// head implies every deeper order is non-crossing as well.  A stale or
/// generation-invalid crossing head must therefore be removed by an
/// authenticated `RemovePruned` action before this predicate can succeed.
pub fn verify_no_crossing_maker_v2(
    root: OrderIndexRootV2,
    taker_side: Side,
    taker_limit_price_atoms: u64,
) -> Result<(), ProtocolError> {
    root.aggregate.validate()?;
    if taker_limit_price_atoms == 0 {
        return Err(ProtocolError::InvalidBondState);
    }
    let crosses = match taker_side {
        Side::Buy => root
            .aggregate
            .best_sell
            .is_some_and(|maker| maker.limit_price_atoms <= taker_limit_price_atoms),
        Side::Sell => root
            .aggregate
            .best_buy
            .is_some_and(|maker| maker.limit_price_atoms >= taker_limit_price_atoms),
    };
    if crosses {
        return Err(ProtocolError::PriceTimePriorityViolation);
    }
    Ok(())
}

/// Authenticate the exact price-time head used by a permissionless
/// liquidation and its one-sided oracle band. For a long target, the highest
/// bid is selected and must be at least `liquidation_low_atoms`; if it is
/// lower, every deeper bid is lower as well. For a short target, the lowest
/// ask is selected and must be at most `liquidation_high_atoms`; if it is
/// higher, every deeper ask is higher as well. No separate eligible-range
/// proof is needed once the immediate predecessor root is authenticated.
pub fn verify_best_liquidation_maker_v2(
    predecessor_root: OrderIndexRootV2,
    maker: &OrderIndexLeafV2,
    context: IncrementalOrderContextV2,
    target_position_size_atoms: i64,
    liquidation_low_atoms: u64,
    liquidation_high_atoms: u64,
) -> Result<u64, ProtocolError> {
    predecessor_root.aggregate.validate()?;
    maker.validate(context)?;
    if target_position_size_atoms == 0
        || liquidation_low_atoms == 0
        || liquidation_high_atoms < liquidation_low_atoms
    {
        return Err(ProtocolError::InvalidBondState);
    }
    let maker_price = maker.signed_order.order.limit_price.get();
    let (expected, within_band, adverse_price) = if target_position_size_atoms > 0 {
        (
            predecessor_root.aggregate.best_buy,
            maker.signed_order.order.side == Side::Buy && maker_price >= liquidation_low_atoms,
            liquidation_low_atoms,
        )
    } else {
        (
            predecessor_root.aggregate.best_sell,
            maker.signed_order.order.side == Side::Sell && maker_price <= liquidation_high_atoms,
            liquidation_high_atoms,
        )
    };
    if expected != Some(maker.priority()) || !within_band {
        return Err(ProtocolError::PriceTimePriorityViolation);
    }
    Ok(adverse_price)
}

/// Typed read-only trader membership multiproof used when generation pruning
/// needs the current trader leaf but that trader is not otherwise updated.
/// Internally the shared traversal computes a hypothetical removal only to
/// reconstruct and compare the authenticated old root; the returned state is
/// discarded and no no-op update is admitted to the transition relation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TraderStateReadBatchProofV2 {
    pub leaves: Vec<TraderLeafV2>,
    pub frontier: Vec<SparseMerkleSumFrontierItemV2>,
}

impl CanonicalEncode for TraderStateReadBatchProofV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u16(out, u16::try_from(self.leaves.len()).unwrap_or(u16::MAX));
        for leaf in &self.leaves {
            leaf.encode_to(out);
        }
        put_u16(out, u16::try_from(self.frontier.len()).unwrap_or(u16::MAX));
        for item in &self.frontier {
            item.encode_to(out);
        }
    }
}

impl TraderStateReadBatchProofV2 {
    fn sparse_proof(
        &self,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<SparseMerkleSumBatchProofV2, ProtocolError> {
        if self.leaves.is_empty()
            || self.leaves.len() > MAX_SPARSE_MERKLE_SUM_UPDATES_PER_BATCH_V2
            || self
                .leaves
                .windows(2)
                .any(|pair| pair[0].key() >= pair[1].key())
        {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        let updates = self
            .leaves
            .iter()
            .map(|leaf| {
                leaf.validate(bounds)?;
                Ok(SparseMerkleSumBatchLeafUpdateV2 {
                    key: leaf.key(),
                    old_leaf: leaf.sparse_leaf(bounds)?,
                    new_leaf: SparseMerkleSumLeafV2::EMPTY,
                })
            })
            .collect::<Result<Vec<_>, ProtocolError>>()?;
        let proof = SparseMerkleSumBatchProofV2 {
            domain: SparseStateDomainV2::Trader,
            updates,
            frontier: self.frontier.clone(),
        };
        proof.canonical_bytes_checked()?;
        Ok(proof)
    }

    pub fn verify(
        &self,
        expected_root: SparseMerkleSumRootV2,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<(), ProtocolError> {
        if expected_root.domain != SparseStateDomainV2::Trader {
            return Err(ProtocolError::InvalidMerkleProof);
        }
        self.sparse_proof(bounds)?.verify_internal(expected_root)?;
        Ok(())
    }
}

/// Bind every locally supplied trader opening in the order transcript to an
/// opened old/new trader leaf from the exact typed trader batch. Expiry-only
/// pruning does not need a generation read; generation pruning does, and a
/// successor must add a typed read-only trader opening when no trader update is
/// otherwise present.
pub fn verify_order_operation_trader_projection_v2(
    operations: &[OrderIndexOperationV2],
    trader_batch: &TraderStateBatchProofV2,
    trader_reads: Option<&TraderStateReadBatchProofV2>,
    expected_trader_root: SparseMerkleSumRootV2,
    context: IncrementalOrderContextV2,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<(), ProtocolError> {
    verify_order_operation_trader_projection_parts_v2(
        operations,
        &trader_batch.updates,
        trader_reads,
        expected_trader_root,
        context,
        bounds,
    )
}

/// Child-proof boundary equivalent to [`verify_order_operation_trader_projection_v2`]
/// that accepts only the typed old/new trader openings. This lets the order
/// child cross-bind the trader child's leaf projection without carrying its
/// shared frontier a second time.
pub fn verify_order_operation_trader_projection_parts_v2(
    operations: &[OrderIndexOperationV2],
    trader_updates: &[TraderStateBatchLeafUpdateV2],
    trader_reads: Option<&TraderStateReadBatchProofV2>,
    expected_trader_root: SparseMerkleSumRootV2,
    context: IncrementalOrderContextV2,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<(), ProtocolError> {
    if let Some(reads) = trader_reads {
        reads.verify(expected_trader_root, bounds)?;
    }
    let mut used_read_traders = BTreeSet::new();
    for operation in operations {
        let expiry_only_prune = operation.kind == OrderIndexOperationKindV2::RemovePruned
            && operation.old_leaf.as_ref().is_some_and(|old| {
                old.signed_order.order.expires_at_height < context.sidechain_height
            });
        let linked = trader_updates.iter().any(|update| {
            update.trader == operation.trader_leaf.trader
                && (update.old_leaf.as_ref() == Some(&operation.trader_leaf)
                    || update.new_leaf.as_ref() == Some(&operation.trader_leaf))
        });
        let read_linked = trader_reads.is_some_and(|reads| {
            reads
                .leaves
                .iter()
                .any(|leaf| leaf == &operation.trader_leaf)
        });
        if read_linked {
            used_read_traders.insert(operation.trader_leaf.trader.0);
        }
        if !linked && !read_linked && !expiry_only_prune {
            return Err(ProtocolError::InvalidMerkleProof);
        }
    }
    if trader_reads.is_some_and(|reads| {
        reads.leaves.len() != used_read_traders.len()
            || reads
                .leaves
                .iter()
                .any(|leaf| !used_read_traders.contains(&leaf.trader.0))
    }) {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    Ok(())
}

/// Exact carried affine maintenance line projected from a trader leaf. This is
/// intentionally separate from the complete deficit indices: the latter
/// compute reserve coverage, while this aggregate proves that every ordinary
/// successor position remains operationally safe at the authenticated adverse
/// price band without reopening all traders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PositionRiskExtremaV2 {
    pub trader: XOnlyKey,
    pub side: DeficitSideV2,
    pub cut_x_numerator: Int256V2,
    pub trader_leaf_commitment: Hash32,
    pub selected_initial_margin_bps: u32,
    pub maintenance_margin_bps: u32,
}

impl PositionRiskExtremaV2 {
    /// Conservative compatibility projection for the finite V2 nested-ceil
    /// maintenance rule. Subtracting two whole quote atoms from exact cash
    /// makes the affine requirement dominate both nested outward roundings.
    pub fn from_trader(
        trader: &TraderLeafV2,
        maintenance_margin_bps: u32,
        bounds: IncrementalAccountingBoundsV2,
    ) -> Result<Option<Self>, ProtocolError> {
        trader.validate(bounds)?;
        if maintenance_margin_bps == 0 || maintenance_margin_bps >= 10_000 {
            return Err(ProtocolError::InvalidRate);
        }
        if trader.position_size_atoms == 0 {
            return Ok(None);
        }
        let bps = 10_000u64;
        let exact_cash_with_cushion =
            trader
                .exact_cash_numerator(bounds)?
                .checked_sub(Int256V2::from_u128(
                    2 * u128::from(EXACT_ACCOUNTING_DENOMINATOR_V2),
                ))?;
        let checkpoint = Int256V2::checked_product_i64_i128(
            trader.position_size_atoms,
            trader.last_funding_index_numerator,
        )?;
        let c = exact_cash_with_cushion
            .checked_sub(trader.signed_cost_basis_numerator)?
            .checked_add(checkpoint)?;
        let size = trader.position_size_atoms.unsigned_abs();
        let cut_x_numerator = if trader.position_size_atoms > 0 {
            c.checked_neg()?.checked_mul_u64(bps)?.ceil_div_u64(size)?
        } else {
            c.checked_mul_u64(bps)?.floor_div_u64(size)?
        };
        let extrema = Self {
            trader: trader.trader,
            side: if trader.position_size_atoms > 0 {
                DeficitSideV2::Long
            } else {
                DeficitSideV2::Short
            },
            cut_x_numerator,
            trader_leaf_commitment: trader.validated_commitment(bounds)?,
            selected_initial_margin_bps: trader.selected_initial_margin_bps,
            maintenance_margin_bps,
        };
        extrema.validate()?;
        Ok(Some(extrema))
    }

    pub fn validate(self) -> Result<(), ProtocolError> {
        self.cut_x_numerator.validate()?;
        XOnlyPublicKey::from_slice(&self.trader.0).map_err(|_| ProtocolError::InvalidBondState)?;
        if self.trader_leaf_commitment == [0; 32]
            || !ALLOWED_INITIAL_MARGIN_BPS_V2.contains(&self.selected_initial_margin_bps)
            || self.maintenance_margin_bps == 0
            || self.maintenance_margin_bps >= 10_000
        {
            return Err(ProtocolError::InvalidBondState);
        }
        Ok(())
    }
}

impl CanonicalEncode for PositionRiskExtremaV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.trader.encode_to(out);
        self.side.encode_to(out);
        self.cut_x_numerator.encode_to(out);
        out.extend_from_slice(&self.trader_leaf_commitment);
        put_u32(out, self.selected_initial_margin_bps);
        put_u32(out, self.maintenance_margin_bps);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RiskExtremaAggregateV2 {
    pub leaf_count: u128,
    pub maximum_long_cut_x_numerator: Option<Int256V2>,
    pub minimum_short_cut_x_numerator: Option<Int256V2>,
    pub minimum_selected_initial_margin_bps: u32,
    pub maximum_selected_initial_margin_bps: u32,
    pub maintenance_margin_bps: u32,
}

impl RiskExtremaAggregateV2 {
    pub const ZERO: Self = Self {
        leaf_count: 0,
        maximum_long_cut_x_numerator: None,
        minimum_short_cut_x_numerator: None,
        minimum_selected_initial_margin_bps: 0,
        maximum_selected_initial_margin_bps: 0,
        maintenance_margin_bps: 0,
    };

    pub fn from_leaf(leaf: PositionRiskExtremaV2) -> Result<Self, ProtocolError> {
        leaf.validate()?;
        Ok(Self {
            leaf_count: 1,
            maximum_long_cut_x_numerator: (leaf.side == DeficitSideV2::Long)
                .then_some(leaf.cut_x_numerator),
            minimum_short_cut_x_numerator: (leaf.side == DeficitSideV2::Short)
                .then_some(leaf.cut_x_numerator),
            minimum_selected_initial_margin_bps: leaf.selected_initial_margin_bps,
            maximum_selected_initial_margin_bps: leaf.selected_initial_margin_bps,
            maintenance_margin_bps: leaf.maintenance_margin_bps,
        })
    }

    pub fn checked_add(self, rhs: Self) -> Result<Self, ProtocolError> {
        if self.leaf_count != 0
            && rhs.leaf_count != 0
            && self.maintenance_margin_bps != rhs.maintenance_margin_bps
        {
            return Err(ProtocolError::InvalidBondState);
        }
        let maximum_long = match (
            self.maximum_long_cut_x_numerator,
            rhs.maximum_long_cut_x_numerator,
        ) {
            (None, value) | (value, None) => value,
            (Some(left), Some(right)) => Some(left.max(right)),
        };
        let minimum_short = match (
            self.minimum_short_cut_x_numerator,
            rhs.minimum_short_cut_x_numerator,
        ) {
            (None, value) | (value, None) => value,
            (Some(left), Some(right)) => Some(left.min(right)),
        };
        let minimum_margin = match (
            self.minimum_selected_initial_margin_bps,
            rhs.minimum_selected_initial_margin_bps,
        ) {
            (0, value) | (value, 0) => value,
            (left, right) => left.min(right),
        };
        let aggregate = Self {
            leaf_count: self
                .leaf_count
                .checked_add(rhs.leaf_count)
                .ok_or(ProtocolError::ArithmeticOverflow)?,
            maximum_long_cut_x_numerator: maximum_long,
            minimum_short_cut_x_numerator: minimum_short,
            minimum_selected_initial_margin_bps: minimum_margin,
            maximum_selected_initial_margin_bps: self
                .maximum_selected_initial_margin_bps
                .max(rhs.maximum_selected_initial_margin_bps),
            maintenance_margin_bps: if self.leaf_count == 0 {
                rhs.maintenance_margin_bps
            } else {
                self.maintenance_margin_bps
            },
        };
        aggregate.validate()?;
        Ok(aggregate)
    }

    pub fn validate(self) -> Result<(), ProtocolError> {
        if self.leaf_count == 0 {
            return if self == Self::ZERO {
                Ok(())
            } else {
                Err(ProtocolError::InvalidBondState)
            };
        }
        for cut in self
            .maximum_long_cut_x_numerator
            .iter()
            .chain(self.minimum_short_cut_x_numerator.iter())
        {
            cut.validate()?;
        }
        if self.leaf_count > MAX_REACHABLE_INCREMENTAL_LEAF_COUNT_V2
            || (self.maximum_long_cut_x_numerator.is_none()
                && self.minimum_short_cut_x_numerator.is_none())
            || !ALLOWED_INITIAL_MARGIN_BPS_V2.contains(&self.minimum_selected_initial_margin_bps)
            || !ALLOWED_INITIAL_MARGIN_BPS_V2.contains(&self.maximum_selected_initial_margin_bps)
            || self.minimum_selected_initial_margin_bps > self.maximum_selected_initial_margin_bps
            || self.maintenance_margin_bps == 0
            || self.maintenance_margin_bps >= 10_000
        {
            return Err(ProtocolError::InvalidBondState);
        }
        Ok(())
    }

    /// Query the authenticated adverse operational band. The caller supplies
    /// Q coordinates already derived from authenticated prices and funding.
    pub fn all_positions_operationally_safe(
        self,
        long_x_numerator: Int256V2,
        short_x_numerator: Int256V2,
    ) -> Result<bool, ProtocolError> {
        self.validate()?;
        long_x_numerator.validate()?;
        short_x_numerator.validate()?;
        Ok(self
            .maximum_long_cut_x_numerator
            .map_or(true, |cut| long_x_numerator >= cut)
            && self
                .minimum_short_cut_x_numerator
                .map_or(true, |cut| short_x_numerator <= cut))
    }
}

/// Convert an authenticated adverse price and global funding index into the
/// side-specific maintenance coordinates used by `PositionRiskExtremaV2`:
///
/// `X_long = price*R*(B-m) - B*F`
/// `X_short = price*R*(B+m) - B*F`.
pub fn operational_risk_coordinates_v2(
    long_price_atoms: u64,
    short_price_atoms: u64,
    global_funding_index_numerator: i128,
    maintenance_margin_bps: u32,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<(Int256V2, Int256V2), ProtocolError> {
    bounds.validate()?;
    validate_exact_funding_index_v2(global_funding_index_numerator)?;
    if long_price_atoms == 0
        || short_price_atoms == 0
        || long_price_atoms > bounds.maximum_price_atoms
        || short_price_atoms > bounds.maximum_price_atoms
        || maintenance_margin_bps == 0
        || maintenance_margin_bps >= 10_000
    {
        return Err(ProtocolError::InvalidRate);
    }
    let bps = 10_000u64;
    let funding = Int256V2::from_i128(global_funding_index_numerator).checked_mul_u64(bps)?;
    let long = Int256V2::from_u128(u128::from(long_price_atoms))
        .checked_mul_u64(FUNDING_INDEX_DENOMINATOR_V2)?
        .checked_mul_u64(bps - u64::from(maintenance_margin_bps))?
        .checked_sub(funding)?;
    let short = Int256V2::from_u128(u128::from(short_price_atoms))
        .checked_mul_u64(FUNDING_INDEX_DENOMINATOR_V2)?
        .checked_mul_u64(bps + u64::from(maintenance_margin_bps))?
        .checked_sub(funding)?;
    Ok((long, short))
}

impl CanonicalEncode for RiskExtremaAggregateV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.leaf_count.to_be_bytes());
        for cut in [
            self.maximum_long_cut_x_numerator,
            self.minimum_short_cut_x_numerator,
        ] {
            match cut {
                None => put_u8(out, 0),
                Some(cut) => {
                    put_u8(out, 1);
                    cut.encode_to(out);
                }
            }
        }
        put_u32(out, self.minimum_selected_initial_margin_bps);
        put_u32(out, self.maximum_selected_initial_margin_bps);
        put_u32(out, self.maintenance_margin_bps);
    }
}

/// Exact touched-position margin replay. Growing exposure or crossing direction
/// uses the stricter carried/signed selection; reductions retain the carried
/// value and flat positions reset to the proof floor.
pub fn replay_selected_position_margin_v2(
    old: &TraderLeafV2,
    next: &mut TraderLeafV2,
    signed_selection_bps: u32,
    proof_floor_bps: u32,
    bounds: IncrementalAccountingBoundsV2,
) -> Result<(), ProtocolError> {
    old.validate(bounds)?;
    next.validate(bounds)?;
    if old.trader != next.trader
        || !ALLOWED_INITIAL_MARGIN_BPS_V2.contains(&signed_selection_bps)
        || !ALLOWED_INITIAL_MARGIN_BPS_V2.contains(&proof_floor_bps)
    {
        return Err(ProtocolError::InvalidBondState);
    }
    let grows_or_crosses = next.position_size_atoms != 0
        && (old.position_size_atoms == 0
            || old.position_size_atoms.signum() != next.position_size_atoms.signum()
            || next.position_size_atoms.unsigned_abs() > old.position_size_atoms.unsigned_abs());
    next.selected_initial_margin_bps = if next.position_size_atoms == 0 {
        proof_floor_bps
    } else if grows_or_crosses {
        old.selected_initial_margin_bps
            .max(signed_selection_bps)
            .max(proof_floor_bps)
    } else {
        old.selected_initial_margin_bps
    };
    next.validate(bounds)
}

#[cfg(test)]
mod tests {
    use num_bigint::{BigInt, Sign};
    use num_traits::Zero as NumZero;
    use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

    use crate::order::OrderFlags;
    use crate::risk::{equity, required_margin, MarginKind};
    use crate::successor_action_v2::{SuccessorLimitOrderV2, SuccessorSignedLimitOrderV2};
    use crate::types::{Amount, Position, Price, Quantity, ECX_USDD_MARKET};

    use super::*;

    fn bounds() -> IncrementalAccountingBoundsV2 {
        IncrementalAccountingBoundsV2 {
            maximum_abs_trader_collateral_atoms: 10_000_000_000_000,
            maximum_total_controlled_atoms: 100_000_000_000_000,
            maximum_abs_position_atoms: 10_000_000_000,
            maximum_open_interest_atoms: 100_000_000_000,
            maximum_price_atoms: 1_000_000_000_000,
        }
    }

    fn i256(value: i128) -> Int256V2 {
        Int256V2::from_i128(value)
    }

    fn int256_from_bigint(value: &BigInt) -> Result<Int256V2, ProtocolError> {
        let (sign, magnitude) = value.to_bytes_be();
        if magnitude.len() > 32 {
            return Err(ProtocolError::ArithmeticOverflow);
        }
        let mut fixed = [0u8; 32];
        fixed[32 - magnitude.len()..].copy_from_slice(&magnitude);
        Int256V2::from_sign_and_magnitude(sign == Sign::Minus, fixed)
            .map_err(|_| ProtocolError::ArithmeticOverflow)
    }

    fn bigint_from_int256(value: Int256V2) -> BigInt {
        let sign = if value.is_negative() {
            Sign::Minus
        } else {
            Sign::Plus
        };
        if value.magnitude().is_zero() {
            BigInt::zero()
        } else {
            BigInt::from_bytes_be(sign, &value.magnitude().to_be_bytes())
        }
    }

    fn trader_key(seed: u8) -> XOnlyKey {
        let secret = SecretKey::from_slice(&[seed; 32]).unwrap();
        let pair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
        let (key, _) = XOnlyPublicKey::from_keypair(&pair);
        XOnlyKey(key.serialize())
    }

    fn order_context() -> IncrementalOrderContextV2 {
        IncrementalOrderContextV2 {
            chain_id: [7; 32],
            market: ECX_USDD_MARKET,
            configuration_hash: [9; 32],
            risk_params: RiskParams::default(),
            sidechain_height: 100,
        }
    }

    fn order_leaf(
        seed: u8,
        side: Side,
        price: u64,
        quantity: u64,
        sequence: u128,
        generation: u128,
    ) -> (OrderIndexLeafV2, TraderLeafV2) {
        let secret = SecretKey::from_slice(&[seed; 32]).unwrap();
        let trader = trader_key(seed);
        let order = SuccessorLimitOrderV2 {
            version: SuccessorLimitOrderV2::VERSION,
            chain_id: [7; 32],
            market: ECX_USDD_MARKET,
            trader,
            side,
            time_in_force: TimeInForce::GoodTilHeight,
            flags: OrderFlags::NONE,
            limit_price: Price::new(price).unwrap(),
            quantity: Quantity::new(quantity).unwrap(),
            client_order_id: [seed; 16],
            max_fee_bps: 5,
            nonce: (1u128 << 96) + u128::from(seed),
            valid_from_height: 90,
            expires_at_height: 200,
        };
        let signed_order = SuccessorSignedLimitOrderV2::sign(order, &secret).unwrap();
        let risk =
            OrderRiskCommitmentV2::sign([9; 32], signed_order.order_id(), trader, 1_000, &secret)
                .unwrap();
        let leaf = OrderIndexLeafV2 {
            version: OrderIndexLeafV2::VERSION,
            signed_order,
            risk,
            remaining_quantity_atoms: quantity,
            received_sequence: sequence,
            admission_receipt_hash: [seed.wrapping_add(32); 32],
            trader_order_generation: generation,
            salt: [seed.wrapping_add(64); 32],
        };
        let mut trader_leaf = flat_leaf(seed);
        trader_leaf.order_generation = generation;
        (leaf, trader_leaf)
    }

    fn flat_leaf(seed: u8) -> TraderLeafV2 {
        TraderLeafV2 {
            version: TraderLeafV2::VERSION,
            trader: trader_key(seed),
            account_nonce: 0,
            collateral_atoms: 100,
            cash_residual_numerator: 0,
            position_size_atoms: 0,
            signed_cost_basis_numerator: Int256V2::ZERO,
            last_funding_index_numerator: 0,
            selected_initial_margin_bps: 1_000,
            order_generation: 0,
            salt: [seed; 32],
        }
    }

    fn one_leaf_root(leaf: &TraderLeafV2) -> SparseMerkleSumRootV2 {
        let update = TraderStateUpdateV2 {
            trader: leaf.trader,
            old_leaf: None,
            new_leaf: Some(leaf.clone()),
            path: canonical_empty_sparse_path_v2(SparseStateDomainV2::Trader),
            continues_previous_key: false,
        };
        verify_chained_trader_updates_v2(
            canonical_empty_sparse_root_v2(SparseStateDomainV2::Trader),
            &[update],
            bounds(),
            1,
        )
        .unwrap()
    }

    #[test]
    fn empty_roots_are_canonical_and_domain_separated() {
        let trader = canonical_empty_sparse_root_v2(SparseStateDomainV2::Trader);
        assert_eq!(
            trader,
            canonical_empty_sparse_root_v2(SparseStateDomainV2::Trader)
        );
        assert!(trader.aggregate.is_zero());
        assert_ne!(
            trader.hash,
            canonical_empty_sparse_root_v2(SparseStateDomainV2::DepositNullifier).hash
        );
        let path = canonical_empty_sparse_path_v2(SparseStateDomainV2::Trader);
        assert_eq!(path.siblings.len(), SPARSE_MERKLE_SUM_DEPTH_V2);
        assert_eq!(
            path.siblings[0],
            canonical_empty_sparse_node_v2(SparseStateDomainV2::Trader, 0).unwrap()
        );
        assert_eq!(
            path.siblings[255],
            canonical_empty_sparse_node_v2(SparseStateDomainV2::Trader, 255).unwrap()
        );
    }

    #[test]
    fn signed_256_is_canonical_bounded_and_matches_bigint_arithmetic() {
        let negative_zero = Int256V2::from_sign_and_magnitude(true, [0; 32]);
        assert_eq!(negative_zero, Err(ProtocolError::NonCanonicalEncoding));

        let positive_limit =
            Int256V2::from_sign_and_magnitude(false, SIGNED_256_MAX_MAGNITUDE_V2.to_be_bytes())
                .unwrap();
        let negative_limit =
            Int256V2::from_sign_and_magnitude(true, SIGNED_256_MAX_MAGNITUDE_V2.to_be_bytes())
                .unwrap();
        let two_to_255 = U256::ONE.shl_vartime(255).to_be_bytes();
        assert_eq!(
            Int256V2::from_sign_and_magnitude(false, two_to_255),
            Err(ProtocolError::NonCanonicalEncoding)
        );
        assert_eq!(
            Int256V2::from_sign_and_magnitude(true, two_to_255),
            Err(ProtocolError::NonCanonicalEncoding)
        );
        assert_eq!(
            positive_limit.checked_add(Int256V2::from_i128(1)),
            Err(ProtocolError::ArithmeticOverflow)
        );
        assert_eq!(
            negative_limit.checked_sub(Int256V2::from_i128(1)),
            Err(ProtocolError::ArithmeticOverflow)
        );

        let samples = [
            i128::MIN + 1,
            -9_876_543_210_987_654_321,
            -17,
            -1,
            0,
            1,
            19,
            9_876_543_210_987_654_321,
            i128::MAX,
        ];
        for lhs in samples {
            for rhs in samples {
                let lhs_i = Int256V2::from_i128(lhs);
                let rhs_i = Int256V2::from_i128(rhs);
                let lhs_b = BigInt::from(lhs);
                let rhs_b = BigInt::from(rhs);
                assert_eq!(
                    bigint_from_int256(lhs_i.checked_add(rhs_i).unwrap()),
                    &lhs_b + &rhs_b
                );
                assert_eq!(
                    bigint_from_int256(lhs_i.checked_sub(rhs_i).unwrap()),
                    &lhs_b - &rhs_b
                );
                assert_eq!(
                    bigint_from_int256(lhs_i.checked_mul_i128(rhs).unwrap()),
                    &lhs_b * &rhs_b
                );
            }
            for divisor in [1u64, 2, 3, 17, u32::MAX as u64, u64::MAX] {
                let input = Int256V2::from_i128(lhs);
                let (quotient, remainder) = input.div_rem_u64_toward_zero(divisor).unwrap();
                let divisor_b = BigInt::from(divisor);
                assert_eq!(bigint_from_int256(quotient), BigInt::from(lhs) / &divisor_b);
                assert_eq!(BigInt::from(remainder), BigInt::from(lhs) % &divisor_b);
            }
        }

        // Differential coverage above i128 uses the exact 255-bit boundary.
        let max_big = bigint_from_int256(positive_limit);
        assert_eq!(int256_from_bigint(&max_big).unwrap(), positive_limit);
        assert_eq!(int256_from_bigint(&(-max_big)).unwrap(), negative_limit);
    }

    #[test]
    fn signed_256_serde_is_fixed_big_endian_and_rejects_noncanonical_values() {
        let value = Int256V2::from_i128(-0x0102_0304_0506);
        let encoded = bincode::serialize(&value).unwrap();
        assert_eq!(encoded.len(), 33);
        assert_eq!(encoded[0], 1);
        assert_eq!(&encoded[1..27], &[0; 26]);
        assert_eq!(&encoded[27..], &[1, 2, 3, 4, 5, 6]);
        assert_eq!(bincode::deserialize::<Int256V2>(&encoded).unwrap(), value);

        let unsigned = Uint256V2::from_u128(0x0102_0304_0506);
        let unsigned_encoded = bincode::serialize(&unsigned).unwrap();
        assert_eq!(unsigned_encoded.len(), 32);
        assert_eq!(&unsigned_encoded[..26], &[0; 26]);
        assert_eq!(&unsigned_encoded[26..], &[1, 2, 3, 4, 5, 6]);
        assert_eq!(
            bincode::deserialize::<Uint256V2>(&unsigned_encoded).unwrap(),
            unsigned
        );

        let negative_zero = bincode::serialize(&(1u8, [0u8; 32])).unwrap();
        assert!(bincode::deserialize::<Int256V2>(&negative_zero).is_err());
        let invalid_sign = bincode::serialize(&(2u8, [1u8; 32])).unwrap();
        assert!(bincode::deserialize::<Int256V2>(&invalid_sign).is_err());
        let outside_range =
            bincode::serialize(&(0u8, U256::ONE.shl_vartime(255).to_be_bytes())).unwrap();
        assert!(bincode::deserialize::<Int256V2>(&outside_range).is_err());
    }

    #[test]
    fn malformed_signed_cost_cannot_enter_a_leaf_commitment_or_path() {
        let mut leaf = flat_leaf(1);
        leaf.position_size_atoms = 1;
        leaf.signed_cost_basis_numerator = Int256V2 {
            negative: true,
            magnitude: Uint256V2::ZERO,
        };
        assert_eq!(
            leaf.sparse_leaf(bounds()),
            Err(ProtocolError::NonCanonicalEncoding)
        );
        let update = TraderStateUpdateV2 {
            trader: leaf.trader,
            old_leaf: None,
            new_leaf: Some(leaf),
            path: canonical_empty_sparse_path_v2(SparseStateDomainV2::Trader),
            continues_previous_key: false,
        };
        assert_eq!(
            verify_chained_trader_updates_v2(
                canonical_empty_sparse_root_v2(SparseStateDomainV2::Trader),
                &[update],
                bounds(),
                1,
            ),
            Err(ProtocolError::NonCanonicalEncoding)
        );
    }

    #[test]
    fn sparse_update_binds_key_leaf_path_hash_and_every_sum() {
        let leaf = flat_leaf(2);
        let update = TraderStateUpdateV2 {
            trader: leaf.trader,
            old_leaf: None,
            new_leaf: Some(leaf.clone()),
            path: canonical_empty_sparse_path_v2(SparseStateDomainV2::Trader),
            continues_previous_key: false,
        };
        let initial = canonical_empty_sparse_root_v2(SparseStateDomainV2::Trader);
        let root =
            verify_chained_trader_updates_v2(initial, std::slice::from_ref(&update), bounds(), 1)
                .unwrap();
        assert_eq!(root.aggregate, leaf.aggregate(bounds()).unwrap());

        let mut mutated = update.clone();
        mutated.trader = trader_key(3);
        assert_eq!(
            verify_chained_trader_updates_v2(initial, &[mutated], bounds(), 1),
            Err(ProtocolError::InvalidMerkleProof)
        );
        let mut mutated = update.clone();
        mutated.new_leaf.as_mut().unwrap().salt[0] ^= 1;
        let substituted =
            verify_chained_trader_updates_v2(initial, &[mutated], bounds(), 1).unwrap();
        assert_ne!(substituted, root);
        let mut mutated = update.clone();
        mutated.path.siblings[17].hash[0] ^= 1;
        assert_eq!(
            verify_chained_trader_updates_v2(initial, &[mutated], bounds(), 1),
            Err(ProtocolError::InvalidMerkleProof)
        );
        let mut mutated = update.clone();
        mutated.path.siblings[17].aggregate.leaf_count = 1;
        assert_eq!(
            verify_chained_trader_updates_v2(initial, &[mutated], bounds(), 1),
            Err(ProtocolError::InvalidMerkleProof)
        );
        let mut mutated = update;
        mutated.path.siblings.pop();
        assert_eq!(
            verify_chained_trader_updates_v2(initial, &[mutated], bounds(), 1),
            Err(ProtocolError::InvalidMerkleProof)
        );
    }

    #[test]
    fn chained_updates_allow_only_immediate_explicit_reopen() {
        let initial_leaf = flat_leaf(4);
        let initial = one_leaf_root(&initial_leaf);
        let path = canonical_empty_sparse_path_v2(SparseStateDomainV2::Trader);
        let mut second = initial_leaf.clone();
        second.account_nonce = 1;
        second.salt = [5; 32];
        let mut third = second.clone();
        third.account_nonce = 2;
        third.salt = [6; 32];
        let updates = vec![
            TraderStateUpdateV2 {
                trader: initial_leaf.trader,
                old_leaf: Some(initial_leaf.clone()),
                new_leaf: Some(second.clone()),
                path: path.clone(),
                continues_previous_key: false,
            },
            TraderStateUpdateV2 {
                trader: initial_leaf.trader,
                old_leaf: Some(second),
                new_leaf: Some(third),
                path,
                continues_previous_key: true,
            },
        ];
        verify_chained_trader_updates_v2(initial, &updates, bounds(), 2).unwrap();

        let mut unmarked = updates.clone();
        unmarked[1].continues_previous_key = false;
        assert_eq!(
            verify_chained_trader_updates_v2(initial, &unmarked, bounds(), 2),
            Err(ProtocolError::DuplicateMerkleKey)
        );
        let mut false_marker = vec![updates[0].clone()];
        false_marker[0].continues_previous_key = true;
        assert_eq!(
            verify_chained_trader_updates_v2(initial, &false_marker, bounds(), 1),
            Err(ProtocolError::DuplicateMerkleKey)
        );
    }

    #[test]
    fn malformed_lengths_and_no_op_updates_reject_before_encoding() {
        let initial_leaf = flat_leaf(22);
        let initial = one_leaf_root(&initial_leaf);
        let path = canonical_empty_sparse_path_v2(SparseStateDomainV2::Trader);
        let sparse_leaf = initial_leaf.sparse_leaf(bounds()).unwrap();
        let raw_no_op = SparseMerkleSumUpdateV2 {
            domain: SparseStateDomainV2::Trader,
            key: initial_leaf.key(),
            old_leaf: sparse_leaf,
            new_leaf: sparse_leaf,
            path: path.clone(),
            continues_previous_key: false,
        };
        assert_eq!(
            canonical_sparse_update_batch_bytes_v2(std::slice::from_ref(&raw_no_op)),
            Err(ProtocolError::InvalidMerkleProof)
        );
        assert_eq!(
            raw_no_op.verify(initial),
            Err(ProtocolError::InvalidMerkleProof)
        );

        let typed_no_op = TraderStateUpdateV2 {
            trader: initial_leaf.trader,
            old_leaf: Some(initial_leaf.clone()),
            new_leaf: Some(initial_leaf.clone()),
            path: path.clone(),
            continues_previous_key: false,
        };
        assert_eq!(
            canonical_trader_update_batch_bytes_v2(std::slice::from_ref(&typed_no_op)),
            Err(ProtocolError::InvalidMerkleProof)
        );
        assert_eq!(
            verify_chained_trader_updates_v2(initial, &[typed_no_op], bounds(), 1),
            Err(ProtocolError::InvalidMerkleProof)
        );

        let mut next_leaf = initial_leaf.clone();
        next_leaf.account_nonce = 1;
        next_leaf.salt = [23; 32];
        let mut short_path = path;
        short_path.siblings.pop();
        let short_typed = TraderStateUpdateV2 {
            trader: initial_leaf.trader,
            old_leaf: Some(initial_leaf),
            new_leaf: Some(next_leaf),
            path: short_path,
            continues_previous_key: false,
        };
        assert_eq!(
            canonical_trader_update_batch_bytes_v2(std::slice::from_ref(&short_typed)),
            Err(ProtocolError::InvalidMerkleProof)
        );
        assert_eq!(
            verify_chained_trader_updates_v2(initial, &[short_typed], bounds(), 1),
            Err(ProtocolError::InvalidMerkleProof)
        );

        let kind = NullifierKindV2::Deposit;
        let oversized_path = SparseNullifierPathV2 {
            kind,
            siblings: vec![
                canonical_empty_nullifier_node_v2(kind, 0).unwrap();
                usize::from(u16::MAX) + 1
            ],
        };
        let oversized = SparseNullifierUpdateV2 {
            kind,
            nullifier: [24; 32],
            path: oversized_path,
        };
        assert!(std::panic::catch_unwind(|| oversized.canonical_bytes()).is_ok());
        assert_eq!(
            canonical_nullifier_update_batch_bytes_v2(std::slice::from_ref(&oversized)),
            Err(ProtocolError::InvalidMerkleProof)
        );
        assert_eq!(
            verify_sparse_nullifier_updates_v2(
                canonical_empty_nullifier_root_v2(kind),
                &[oversized],
                1,
            ),
            Err(ProtocolError::InvalidMerkleProof)
        );

        let no_op_shared = SparseMerkleSumBatchLeafUpdateV2 {
            key: [25; 32],
            old_leaf: SparseMerkleSumLeafV2::EMPTY,
            new_leaf: SparseMerkleSumLeafV2::EMPTY,
        };
        assert_eq!(
            SparseMerkleSumBatchProofV2::for_canonical_empty_root(
                SparseStateDomainV2::Trader,
                vec![no_op_shared],
            ),
            Err(ProtocolError::InvalidMerkleProof)
        );
    }

    #[test]
    fn shared_frontier_batch_is_complete_canonical_and_compact() {
        let unit = TraderAggregateV2 {
            leaf_count: 1,
            ..TraderAggregateV2::ZERO
        };
        let mut updates = Vec::with_capacity(MAX_SPARSE_MERKLE_SUM_UPDATES_PER_BATCH_V2);
        for index in 0..MAX_SPARSE_MERKLE_SUM_UPDATES_PER_BATCH_V2 {
            // These keys occupy all 64 six-bit root prefixes.  Their remaining
            // 250 levels are canonical empty, which is the raw-path worst case
            // that the one-byte shared frontier compresses.
            let mut key = [0u8; 32];
            key[0] = u8::try_from(index * 4).unwrap();
            updates.push(SparseMerkleSumBatchLeafUpdateV2 {
                key,
                old_leaf: SparseMerkleSumLeafV2::EMPTY,
                new_leaf: SparseMerkleSumLeafV2::present(
                    tagged_hash("ECX/test/shared-frontier-leaf", &key),
                    unit,
                )
                .unwrap(),
            });
        }
        let proof = SparseMerkleSumBatchProofV2::for_canonical_empty_root(
            SparseStateDomainV2::Trader,
            updates,
        )
        .unwrap();
        assert_eq!(proof.frontier.len(), 16_000);
        let encoded = proof.canonical_bytes_checked().unwrap();
        assert_eq!(encoded.len(), 64_645);
        assert!(encoded.len() * 20 < 3_250_000);
        let initial = canonical_empty_sparse_root_v2(SparseStateDomainV2::Trader);
        let next = proof.verify_internal(initial).unwrap();
        assert_eq!(
            proof.verify(initial),
            Err(ProtocolError::InvalidMerkleProof)
        );
        assert_eq!(next.aggregate.leaf_count, 64);

        let mut missing = proof.clone();
        missing.frontier.pop();
        assert_eq!(
            missing.verify_internal(initial),
            Err(ProtocolError::InvalidMerkleProof)
        );
        let mut trailing = proof.clone();
        trailing
            .frontier
            .push(SparseMerkleSumFrontierItemV2::CanonicalEmpty);
        assert_eq!(
            trailing.verify_internal(initial),
            Err(ProtocolError::InvalidMerkleProof)
        );
        let mut unsorted = proof.clone();
        unsorted.updates.swap(0, 1);
        assert_eq!(
            unsorted.verify_internal(initial),
            Err(ProtocolError::InvalidMerkleProof)
        );
        let mut duplicate = proof.clone();
        duplicate.updates[1].key = duplicate.updates[0].key;
        assert_eq!(
            duplicate.verify_internal(initial),
            Err(ProtocolError::InvalidMerkleProof)
        );
        let mut noncanonical = proof.clone();
        noncanonical.frontier[0] = SparseMerkleSumFrontierItemV2::Occupied(
            canonical_empty_sparse_node_v2(SparseStateDomainV2::Trader, 0).unwrap(),
        );
        assert_eq!(
            noncanonical.verify_internal(initial),
            Err(ProtocolError::NonCanonicalEncoding)
        );

        // Every omitted subtree can be occupied in a reachable populated
        // tree. This is the maximum 64-key wire shape: 16,000 occupied
        // frontier items at 364 bytes each, plus 48,645 bytes of headers and
        // old/new leaf replacements.
        let mut all_occupied = proof.clone();
        for (index, item) in all_occupied.frontier.iter_mut().enumerate() {
            *item = SparseMerkleSumFrontierItemV2::Occupied(SparseMerkleSumNodeV2 {
                hash: tagged_hash("ECX/test/shared-frontier-occupied", &index.to_be_bytes()),
                aggregate: unit,
            });
        }
        let all_occupied_bytes = all_occupied.canonical_bytes_checked().unwrap();
        assert_eq!(all_occupied.frontier.len(), 16_000);
        assert_eq!(all_occupied_bytes.len(), 5_872_645);
        assert!(all_occupied_bytes.len() < MAX_SPARSE_MERKLE_SUM_UPDATE_BATCH_BYTES_V2);

        let canonical_empty_nodes =
            canonical_empty_sparse_nodes_v2(SparseStateDomainV2::Trader).unwrap();
        let mut frontier_cursor = 0;
        let (occupied_old, occupied_new) = compute_sparse_batch_subtree_v2(
            SparseStateDomainV2::Trader,
            0,
            &all_occupied.updates,
            &all_occupied.frontier,
            &mut frontier_cursor,
            &canonical_empty_nodes,
        )
        .unwrap();
        assert_eq!(frontier_cursor, 16_000);
        let occupied_initial =
            SparseMerkleSumRootV2::from_node(SparseStateDomainV2::Trader, occupied_old);
        let occupied_next = all_occupied.verify_internal(occupied_initial).unwrap();
        assert_eq!(
            occupied_next,
            SparseMerkleSumRootV2::from_node(SparseStateDomainV2::Trader, occupied_new)
        );
        assert_eq!(occupied_initial.aggregate.leaf_count, 16_000);
        assert_eq!(occupied_next.aggregate.leaf_count, 16_064);

        let mut substituted = proof;
        substituted.frontier[0] = SparseMerkleSumFrontierItemV2::Occupied(SparseMerkleSumNodeV2 {
            hash: [99; 32],
            aggregate: TraderAggregateV2::ZERO,
        });
        assert_eq!(
            substituted.verify_internal(initial),
            Err(ProtocolError::InvalidMerkleProof)
        );
    }

    #[test]
    fn typed_shared_frontier_derives_trader_commitments_aggregates_and_keys() {
        let mut flat_debt = flat_leaf(26);
        flat_debt.collateral_atoms = 0;
        flat_debt.cash_residual_numerator = -7;
        let mut open_debt = flat_leaf(27);
        open_debt.collateral_atoms = 0;
        open_debt.cash_residual_numerator = -9;
        open_debt.position_size_atoms = 1;
        open_debt.signed_cost_basis_numerator = i256(i128::from(FUNDING_INDEX_DENOMINATOR_V2));

        let mut updates = vec![
            TraderStateBatchLeafUpdateV2 {
                trader: flat_debt.trader,
                old_leaf: None,
                new_leaf: Some(flat_debt.clone()),
            },
            TraderStateBatchLeafUpdateV2 {
                trader: open_debt.trader,
                old_leaf: None,
                new_leaf: Some(open_debt.clone()),
            },
        ];
        updates.sort_by_key(|update| update.trader.0);
        let proof = TraderStateBatchProofV2::for_canonical_empty_root(updates, bounds()).unwrap();
        let initial = canonical_empty_sparse_root_v2(SparseStateDomainV2::Trader);
        let next = proof.verify(initial, bounds(), 2).unwrap();
        let expected = flat_debt
            .aggregate(bounds())
            .unwrap()
            .checked_add(open_debt.aggregate(bounds()).unwrap())
            .unwrap();
        assert_eq!(next.aggregate, expected);
        assert_eq!(
            next.aggregate.flat_negative_exact_cash_numerator,
            Uint256V2::from_u64(7)
        );
        assert_eq!(
            proof.updates[0].sparse_update(bounds()).unwrap().key,
            proof.updates[0].trader.0
        );
        let opened = proof.updates[0].new_leaf.as_ref().unwrap();
        let derived = proof.updates[0].sparse_update(bounds()).unwrap().new_leaf;
        assert_eq!(
            derived,
            SparseMerkleSumLeafV2::present(
                opened.validated_commitment(bounds()).unwrap(),
                opened.aggregate(bounds()).unwrap(),
            )
            .unwrap()
        );

        // The generic primitive deliberately accepts opaque leaf data. The
        // typed trader wrapper has no such fields and always derives both from
        // the opened trader leaf under the accounting bounds.
        let opaque_aggregate = TraderAggregateV2 {
            leaf_count: 1,
            ..TraderAggregateV2::ZERO
        };
        let opaque = SparseMerkleSumBatchProofV2::for_canonical_empty_root(
            SparseStateDomainV2::Trader,
            vec![SparseMerkleSumBatchLeafUpdateV2 {
                key: [1; 32],
                old_leaf: SparseMerkleSumLeafV2::EMPTY,
                new_leaf: SparseMerkleSumLeafV2::present([42; 32], opaque_aggregate).unwrap(),
            }],
        )
        .unwrap();
        opaque.verify_internal(initial).unwrap();
        assert_eq!(
            opaque.verify(initial),
            Err(ProtocolError::InvalidMerkleProof)
        );

        let mut wrong_trader = proof.clone();
        wrong_trader.updates[0].trader = trader_key(28);
        assert_eq!(
            wrong_trader.verify(initial, bounds(), 2),
            Err(ProtocolError::InvalidMerkleProof)
        );
        let mut wrong_old_root = initial;
        wrong_old_root.aggregate = opaque_aggregate;
        assert_eq!(
            proof.verify(wrong_old_root, bounds(), 2),
            Err(ProtocolError::InvalidBondState)
        );
        let mut missing = proof.clone();
        missing.frontier.pop();
        assert_eq!(
            missing.verify(initial, bounds(), 2),
            Err(ProtocolError::InvalidMerkleProof)
        );
        let no_op_leaf = flat_leaf(29);
        assert_eq!(
            TraderStateBatchProofV2::for_canonical_empty_root(
                vec![TraderStateBatchLeafUpdateV2 {
                    trader: no_op_leaf.trader,
                    old_leaf: Some(no_op_leaf.clone()),
                    new_leaf: Some(no_op_leaf),
                }],
                bounds(),
            ),
            Err(ProtocolError::InvalidMerkleProof)
        );
    }

    #[test]
    fn gross_trader_cash_uses_reachable_leaf_envelope_not_physical_supply() {
        let configured = bounds();
        let expected = configured
            .maximum_abs_trader_collateral_atoms
            .checked_mul(MAX_REACHABLE_INCREMENTAL_LEAF_COUNT_V2)
            .unwrap();
        assert_eq!(
            configured
                .maximum_reachable_gross_trader_cash_atoms()
                .unwrap(),
            expected
        );
        assert!(expected > configured.maximum_total_controlled_atoms);

        // Six winners and six debtors have zero signed cash, but gross cash is
        // 120T atoms, above the 100T physical controlled-supply bound. This is
        // a valid authenticated arithmetic state; solvency separately binds
        // the negative side to insurance and deficit roots.
        let mut aggregate = TraderAggregateV2::ZERO;
        for index in 30..42 {
            let mut leaf = flat_leaf(index);
            leaf.collateral_atoms = if index < 36 {
                i128::try_from(configured.maximum_abs_trader_collateral_atoms).unwrap()
            } else {
                -i128::try_from(configured.maximum_abs_trader_collateral_atoms).unwrap()
            };
            aggregate = aggregate
                .checked_add(leaf.aggregate(configured).unwrap())
                .unwrap();
        }
        assert_eq!(aggregate.total_collateral_atoms, 0);
        assert!(aggregate.gross_collateral_atoms > configured.maximum_total_controlled_atoms);
        aggregate.validate(configured).unwrap();
        let root = SparseMerkleSumRootV2 {
            domain: SparseStateDomainV2::Trader,
            hash: [81; 32],
            aggregate,
        };
        let expected = Int256V2::from_u128(1_000)
            .checked_mul_u64(EXACT_ACCOUNTING_DENOMINATOR_V2)
            .unwrap();
        assert_eq!(
            controlled_value_numerator_v2(root, PRICE_SCALE, 0, 1_000, configured).unwrap(),
            expected
        );
        verify_controlled_value_v2(root, PRICE_SCALE, 0, 1_000, expected, configured).unwrap();
        assert_eq!(
            controlled_value_numerator_v2(
                root,
                PRICE_SCALE,
                0,
                configured.maximum_total_controlled_atoms + 1,
                configured,
            ),
            Err(ProtocolError::InvalidBondState)
        );
        let unphysical_expected =
            Int256V2::from_u128(configured.maximum_total_controlled_atoms + 1)
                .checked_mul_u64(EXACT_ACCOUNTING_DENOMINATOR_V2)
                .unwrap();
        assert_eq!(
            verify_controlled_value_v2(
                root,
                PRICE_SCALE,
                0,
                1_000,
                unphysical_expected,
                configured,
            ),
            Err(ProtocolError::InvalidBondState)
        );

        let impossible_bounds = IncrementalAccountingBoundsV2 {
            maximum_abs_trader_collateral_atoms: i128::MAX as u128,
            maximum_total_controlled_atoms: i128::MAX as u128,
            ..configured
        };
        assert_eq!(
            impossible_bounds.validate(),
            Err(ProtocolError::ArithmeticOverflow)
        );
    }

    fn deficit_line(
        side: DeficitSideV2,
        trader_seed: u8,
        intercept: i128,
        size_atoms: u64,
    ) -> DeficitIndexLeafV2 {
        let intercept_numerator = i256(intercept);
        let cut_q_numerator = match side {
            DeficitSideV2::Long => intercept_numerator.ceil_div_u64(size_atoms).unwrap(),
            DeficitSideV2::Short => intercept_numerator.floor_div_u64(size_atoms).unwrap(),
        };
        DeficitIndexLeafV2 {
            version: DeficitIndexLeafV2::VERSION,
            side,
            trader: trader_key(trader_seed),
            cut_q_numerator,
            size_atoms,
            intercept_numerator,
            trader_leaf_commitment: [trader_seed; 32],
        }
    }

    fn combine_deficit_test_nodes(
        side: DeficitSideV2,
        height: usize,
        left: DeficitIndexNodeV2,
        right: DeficitIndexNodeV2,
    ) -> DeficitIndexNodeV2 {
        let aggregate = left.aggregate.checked_add(right.aggregate).unwrap();
        DeficitIndexNodeV2 {
            hash: deficit_index_parent_hash_v2(
                side,
                u16::try_from(height).unwrap(),
                left,
                right,
                aggregate,
            ),
            aggregate,
        }
    }

    fn single_line_deficit_root(line: DeficitIndexLeafV2) -> DeficitIndexRootV2 {
        let key = line.key().ordered_bytes().unwrap();
        let empty = canonical_empty_deficit_index_nodes_v2(line.side).unwrap();
        let mut current = deficit_index_line_leaf_node_v2(line, bounds()).unwrap();
        for depth in (0..DEFICIT_INDEX_DEPTH_V2).rev() {
            let sibling = empty[DEFICIT_INDEX_DEPTH_V2 - depth - 1];
            current = if deficit_index_key_bit_msb_first_v2(&key, depth).unwrap() {
                combine_deficit_test_nodes(
                    line.side,
                    DEFICIT_INDEX_DEPTH_V2 - depth,
                    sibling,
                    current,
                )
            } else {
                combine_deficit_test_nodes(
                    line.side,
                    DEFICIT_INDEX_DEPTH_V2 - depth,
                    current,
                    sibling,
                )
            };
        }
        DeficitIndexRootV2::from_node(line.side, current)
    }

    fn canonical_empty_deficit_update(
        kind: DeficitIndexMutationKindV2,
        trader_leaf: TraderLeafV2,
    ) -> DeficitIndexUpdateV2 {
        let side = DeficitIndexLeafV2::from_trader(&trader_leaf, bounds())
            .unwrap()
            .unwrap()
            .side;
        DeficitIndexUpdateV2 {
            side,
            kind,
            trader_leaf,
            siblings_root_to_leaf: vec![
                DeficitIndexPathItemV2::CanonicalEmpty;
                DEFICIT_INDEX_DEPTH_V2
            ],
        }
    }

    fn long_leaf_at_price(seed: u8, price_atoms: u64, salt: u8) -> TraderLeafV2 {
        let mut leaf = flat_leaf(seed);
        leaf.collateral_atoms = 0;
        leaf.position_size_atoms = 1;
        leaf.signed_cost_basis_numerator =
            Int256V2::from_u128(u128::from(price_atoms) * u128::from(FUNDING_INDEX_DENOMINATOR_V2));
        leaf.salt = [salt; 32];
        leaf
    }

    fn sorted_deficit_batch_mutations(
        side: DeficitSideV2,
        mut mutations: Vec<DeficitIndexBatchMutationV2>,
    ) -> Vec<DeficitIndexBatchMutationV2> {
        mutations.sort_by(|left, right| {
            let left = left.derive(side, bounds()).unwrap();
            let right = right.derive(side, bounds()).unwrap();
            left.key
                .cmp(&right.key)
                .then_with(|| left.kind.code().cmp(&right.kind.code()))
        });
        mutations
    }

    fn single_line_deficit_range_proof(
        line: DeficitIndexLeafV2,
        q_numerator: Int256V2,
    ) -> DeficitIndexRangeProofV2 {
        let line_key = line.key().ordered_bytes().unwrap();
        let boundary = deficit_index_boundary_key_v2(line.side, q_numerator).unwrap();
        let divergence = (0..DEFICIT_INDEX_DEPTH_V2)
            .find(|depth| {
                deficit_index_key_bit_msb_first_v2(&line_key, *depth).unwrap()
                    != deficit_index_key_bit_msb_first_v2(&boundary, *depth).unwrap()
            })
            .unwrap();
        let empty = canonical_empty_deficit_index_nodes_v2(line.side).unwrap();
        let mut line_subtree = deficit_index_line_leaf_node_v2(line, bounds()).unwrap();
        for depth in ((divergence + 1)..DEFICIT_INDEX_DEPTH_V2).rev() {
            let sibling = empty[DEFICIT_INDEX_DEPTH_V2 - depth - 1];
            line_subtree = if deficit_index_key_bit_msb_first_v2(&line_key, depth).unwrap() {
                combine_deficit_test_nodes(
                    line.side,
                    DEFICIT_INDEX_DEPTH_V2 - depth,
                    sibling,
                    line_subtree,
                )
            } else {
                combine_deficit_test_nodes(
                    line.side,
                    DEFICIT_INDEX_DEPTH_V2 - depth,
                    line_subtree,
                    sibling,
                )
            };
        }
        let mut proof =
            DeficitIndexRangeProofV2::for_canonical_empty_root(line.side, q_numerator, bounds())
                .unwrap();
        proof.siblings_root_to_leaf[divergence] = DeficitIndexPathItemV2::Occupied(line_subtree);
        proof
    }

    #[test]
    fn ordered_deficit_range_proof_is_strict_complete_and_nonmember() {
        assert_eq!(i256(-5).floor_div_u64(2).unwrap(), i256(-3));
        assert_eq!(i256(-5).ceil_div_u64(2).unwrap(), i256(-2));
        let signed_boundary_order =
            [-2, -1, 0, 1, 2].map(|value| signed_numeric_order_key_v2(i256(value)).unwrap());
        assert!(signed_boundary_order
            .windows(2)
            .all(|pair| pair[0] < pair[1]));

        let long = deficit_line(DeficitSideV2::Long, 55, 10, 2);
        let long_root = single_line_deficit_root(long);
        let at_cut = single_line_deficit_range_proof(long, i256(5));
        assert_eq!(
            at_cut.verify(long_root, bounds()).unwrap(),
            DeficitRangeAggregateV2::ZERO
        );
        let below_cut = single_line_deficit_range_proof(long, i256(4));
        let selected = below_cut.verify(long_root, bounds()).unwrap();
        assert_eq!(selected.leaf_count, 1);
        assert_eq!(
            selected
                .deficit_numerator(DeficitSideV2::Long, i256(4), bounds())
                .unwrap(),
            Uint256V2::from_u64(2)
        );
        assert_eq!(
            single_line_deficit_range_proof(long, i256(6))
                .verify(long_root, bounds())
                .unwrap(),
            DeficitRangeAggregateV2::ZERO
        );

        let short = deficit_line(DeficitSideV2::Short, 56, -5, 2);
        let short_root = single_line_deficit_root(short);
        assert_eq!(
            single_line_deficit_range_proof(short, i256(-3))
                .verify(short_root, bounds())
                .unwrap(),
            DeficitRangeAggregateV2::ZERO
        );
        let selected = single_line_deficit_range_proof(short, i256(-2))
            .verify(short_root, bounds())
            .unwrap();
        assert_eq!(
            selected
                .deficit_numerator(DeficitSideV2::Short, i256(-2), bounds())
                .unwrap(),
            Uint256V2::from_u64(1)
        );

        let long_sentinel = deficit_index_boundary_key_v2(DeficitSideV2::Long, i256(5)).unwrap();
        let short_sentinel = deficit_index_boundary_key_v2(DeficitSideV2::Short, i256(-3)).unwrap();
        assert_eq!(&long_sentinel[33..], &[0xff; 32]);
        assert_eq!(&short_sentinel[33..], &[0; 32]);
        assert!(XOnlyPublicKey::from_slice(&long_sentinel[33..]).is_err());
        assert!(XOnlyPublicKey::from_slice(&short_sentinel[33..]).is_err());

        let mut substituted = below_cut.clone();
        let occupied = substituted
            .siblings_root_to_leaf
            .iter_mut()
            .find_map(|item| match item {
                DeficitIndexPathItemV2::Occupied(node) => Some(node),
                DeficitIndexPathItemV2::CanonicalEmpty => None,
            })
            .unwrap();
        occupied.hash[0] ^= 1;
        assert_eq!(
            substituted.verify(long_root, bounds()),
            Err(ProtocolError::InvalidMerkleProof)
        );
        let mut wrong_q = below_cut.clone();
        wrong_q.q_numerator = i256(3);
        assert_eq!(
            wrong_q.verify(long_root, bounds()),
            Err(ProtocolError::InvalidMerkleProof)
        );
        let mut short_path = below_cut.clone();
        short_path.siblings_root_to_leaf.pop();
        assert_eq!(
            short_path.verify(long_root, bounds()),
            Err(ProtocolError::InvalidMerkleProof)
        );
        let mut wrong_root = long_root;
        wrong_root.aggregate.total_size_atoms += 1;
        assert_eq!(
            below_cut.verify(wrong_root, bounds()),
            Err(ProtocolError::InvalidMerkleProof)
        );

        let positive_limit =
            Int256V2::from_sign_and_magnitude(false, SIGNED_256_MAX_MAGNITUDE_V2.to_be_bytes())
                .unwrap();
        assert_eq!(
            DeficitRangeAggregateV2 {
                leaf_count: 1,
                total_size_atoms: 1,
                total_intercept_numerator: positive_limit,
            }
            .checked_add(DeficitRangeAggregateV2 {
                leaf_count: 1,
                total_size_atoms: 1,
                total_intercept_numerator: i256(1),
            }),
            Err(ProtocolError::ArithmeticOverflow)
        );
    }

    #[test]
    fn ordered_deficit_range_max_path_is_bounded_and_iterative() {
        let unit = DeficitRangeAggregateV2 {
            leaf_count: 1,
            total_size_atoms: 1,
            total_intercept_numerator: i256(1),
        };
        let mut proof = DeficitIndexRangeProofV2::for_canonical_empty_root(
            DeficitSideV2::Long,
            Int256V2::ZERO,
            bounds(),
        )
        .unwrap();
        for (index, item) in proof.siblings_root_to_leaf.iter_mut().enumerate() {
            *item = DeficitIndexPathItemV2::Occupied(DeficitIndexNodeV2 {
                hash: tagged_hash("ECX/test/deficit-range-occupied", &index.to_be_bytes()),
                aggregate: unit,
            });
        }
        let bytes = proof.canonical_bytes_checked().unwrap();
        assert_eq!(bytes.len(), 50_997);
        assert!(bytes.len() < MAX_DEFICIT_INDEX_RANGE_PROOF_BYTES_V2);
        let (root, selected) = proof.compute(bounds()).unwrap();
        assert!(selected.leaf_count > 0);
        assert_eq!(proof.verify(root, bounds()).unwrap(), selected);

        let mut trailing = proof.clone();
        trailing
            .siblings_root_to_leaf
            .push(DeficitIndexPathItemV2::CanonicalEmpty);
        assert_eq!(
            trailing.verify(root, bounds()),
            Err(ProtocolError::InvalidMerkleProof)
        );
        let mut impossible_leaf_count = proof;
        if let DeficitIndexPathItemV2::Occupied(node) =
            &mut impossible_leaf_count.siblings_root_to_leaf[DEFICIT_INDEX_DEPTH_V2 - 1]
        {
            node.aggregate.leaf_count = 2;
            node.aggregate.total_size_atoms = 2;
        }
        assert_eq!(
            impossible_leaf_count.verify(root, bounds()),
            Err(ProtocolError::InvalidMerkleProof)
        );
    }

    #[test]
    fn typed_deficit_index_updates_bind_trader_projection_and_chain_roots() {
        let old_flat = flat_leaf(57);
        let mut first_long = old_flat.clone();
        first_long.position_size_atoms = 2;
        first_long.signed_cost_basis_numerator =
            i256(10 * i128::from(FUNDING_INDEX_DENOMINATOR_V2));
        first_long.last_funding_index_numerator = 3;
        first_long.salt = [58; 32];
        let trader_update = TraderStateBatchLeafUpdateV2 {
            trader: old_flat.trader,
            old_leaf: Some(old_flat),
            new_leaf: Some(first_long.clone()),
        };
        let insert =
            canonical_empty_deficit_update(DeficitIndexMutationKindV2::Insert, first_long.clone());
        verify_trader_deficit_index_update_projection_v2(
            std::slice::from_ref(&trader_update),
            std::slice::from_ref(&insert),
            &[],
            bounds(),
        )
        .unwrap();

        let empty = canonical_empty_deficit_index_root_v2(DeficitSideV2::Long).unwrap();
        let first_root = verify_chained_deficit_index_updates_v2(
            empty,
            std::slice::from_ref(&insert),
            bounds(),
            1,
        )
        .unwrap();
        let first_line = DeficitIndexLeafV2::from_trader(&first_long, bounds())
            .unwrap()
            .unwrap();
        assert_eq!(first_root, single_line_deficit_root(first_line));

        let remove =
            canonical_empty_deficit_update(DeficitIndexMutationKindV2::Remove, first_long.clone());
        assert_eq!(
            verify_chained_deficit_index_updates_v2(
                first_root,
                std::slice::from_ref(&remove),
                bounds(),
                1,
            )
            .unwrap(),
            empty
        );

        // A changed non-flat affine line is projected as an exact removal
        // followed by an insertion. Both full paths chain through the
        // canonical empty root in this single-line fixture.
        let mut second_long = first_long.clone();
        second_long.account_nonce = 1;
        second_long.position_size_atoms = 3;
        second_long.signed_cost_basis_numerator =
            i256(21 * i128::from(FUNDING_INDEX_DENOMINATOR_V2));
        second_long.salt = [59; 32];
        let changed = TraderStateBatchLeafUpdateV2 {
            trader: first_long.trader,
            old_leaf: Some(first_long.clone()),
            new_leaf: Some(second_long.clone()),
        };
        let insert_second =
            canonical_empty_deficit_update(DeficitIndexMutationKindV2::Insert, second_long.clone());
        let changed_updates = vec![remove.clone(), insert_second.clone()];
        verify_trader_deficit_index_update_projection_v2(
            std::slice::from_ref(&changed),
            &changed_updates,
            &[],
            bounds(),
        )
        .unwrap();
        let second_root =
            verify_chained_deficit_index_updates_v2(first_root, &changed_updates, bounds(), 2)
                .unwrap();
        assert_eq!(
            second_root,
            single_line_deficit_root(
                DeficitIndexLeafV2::from_trader(&second_long, bounds())
                    .unwrap()
                    .unwrap()
            )
        );

        let mut substituted_leaf = insert.clone();
        substituted_leaf.trader_leaf.salt[0] ^= 1;
        assert_eq!(
            verify_trader_deficit_index_update_projection_v2(
                std::slice::from_ref(&trader_update),
                &[substituted_leaf],
                &[],
                bounds(),
            ),
            Err(ProtocolError::InvalidMerkleProof)
        );
        let mut wrong_kind = insert.clone();
        wrong_kind.kind = DeficitIndexMutationKindV2::Remove;
        assert_eq!(
            verify_trader_deficit_index_update_projection_v2(
                std::slice::from_ref(&trader_update),
                &[wrong_kind],
                &[],
                bounds(),
            ),
            Err(ProtocolError::InvalidMerkleProof)
        );
        let mut wrong_side = insert.clone();
        wrong_side.side = DeficitSideV2::Short;
        assert_eq!(
            verify_trader_deficit_index_update_projection_v2(
                std::slice::from_ref(&trader_update),
                &[],
                &[wrong_side],
                bounds(),
            ),
            Err(ProtocolError::InvalidMerkleProof)
        );
        assert_eq!(
            verify_trader_deficit_index_update_projection_v2(
                std::slice::from_ref(&trader_update),
                &[],
                &[],
                bounds(),
            ),
            Err(ProtocolError::InvalidMerkleProof)
        );
        let mut reordered = changed_updates.clone();
        reordered.swap(0, 1);
        assert_eq!(
            verify_trader_deficit_index_update_projection_v2(&[changed], &reordered, &[], bounds(),),
            Err(ProtocolError::InvalidMerkleProof)
        );

        let mut occupied_path = insert.clone();
        occupied_path.siblings_root_to_leaf[0] =
            DeficitIndexPathItemV2::Occupied(DeficitIndexNodeV2 {
                hash: [91; 32],
                aggregate: DeficitRangeAggregateV2 {
                    leaf_count: 1,
                    total_size_atoms: 1,
                    total_intercept_numerator: Int256V2::ZERO,
                },
            });
        assert_eq!(
            occupied_path.verify(empty, bounds()),
            Err(ProtocolError::InvalidMerkleProof)
        );
        let mut short_path = insert;
        short_path.siblings_root_to_leaf.pop();
        assert_eq!(
            short_path.verify(empty, bounds()),
            Err(ProtocolError::InvalidMerkleProof)
        );
    }

    #[test]
    fn typed_deficit_update_full_path_batch_has_isolated_exact_bound() {
        let mut long = flat_leaf(92);
        long.position_size_atoms = 1;
        long.signed_cost_basis_numerator = i256(i128::from(FUNDING_INDEX_DENOMINATOR_V2));
        long.salt = [93; 32];
        let mut update = canonical_empty_deficit_update(DeficitIndexMutationKindV2::Insert, long);
        let unit = DeficitRangeAggregateV2 {
            leaf_count: 1,
            total_size_atoms: 1,
            total_intercept_numerator: Int256V2::ZERO,
        };
        for (index, item) in update.siblings_root_to_leaf.iter_mut().enumerate() {
            *item = DeficitIndexPathItemV2::Occupied(DeficitIndexNodeV2 {
                hash: tagged_hash("ECX/test/deficit-update-occupied", &index.to_be_bytes()),
                aggregate: unit,
            });
        }
        let encoded = update.canonical_bytes_checked(bounds()).unwrap();
        assert_eq!(encoded.len(), 51_147);
        assert!(encoded.len() < MAX_DEFICIT_INDEX_UPDATE_BYTES_V2);

        let updates = vec![update.clone(); MAX_DEFICIT_INDEX_UPDATES_PER_BATCH_V2];
        let batch = canonical_deficit_index_update_batch_bytes_v2(&updates, bounds()).unwrap();
        assert_eq!(batch.len(), 6_546_819);
        assert!(batch.len() < MAX_CHAINED_DEFICIT_INDEX_UPDATE_BATCH_BYTES_V2);
        let mut oversized = updates;
        oversized.push(update);
        assert_eq!(
            canonical_deficit_index_update_batch_bytes_v2(&oversized, bounds()),
            Err(ProtocolError::InvalidMerkleProof)
        );
    }

    #[test]
    fn compact_deficit_shared_frontier_is_typed_complete_and_projected() {
        let old_flat_a = flat_leaf(94);
        let old_flat_b = flat_leaf(95);
        let long_a = long_leaf_at_price(94, 101, 96);
        let long_b = long_leaf_at_price(95, 202, 97);
        let mut trader_updates = vec![
            TraderStateBatchLeafUpdateV2 {
                trader: old_flat_a.trader,
                old_leaf: Some(old_flat_a),
                new_leaf: Some(long_a.clone()),
            },
            TraderStateBatchLeafUpdateV2 {
                trader: old_flat_b.trader,
                old_leaf: Some(old_flat_b),
                new_leaf: Some(long_b.clone()),
            },
        ];
        trader_updates.sort_by_key(|update| update.trader.0);
        let mutations = sorted_deficit_batch_mutations(
            DeficitSideV2::Long,
            vec![
                DeficitIndexBatchMutationV2 {
                    kind: DeficitIndexMutationKindV2::Insert,
                    trader_leaf: long_a.clone(),
                },
                DeficitIndexBatchMutationV2 {
                    kind: DeficitIndexMutationKindV2::Insert,
                    trader_leaf: long_b.clone(),
                },
            ],
        );
        let proof = DeficitIndexBatchProofV2::for_canonical_empty_root(
            DeficitSideV2::Long,
            mutations,
            bounds(),
        )
        .unwrap();
        let empty = canonical_empty_deficit_index_root_v2(DeficitSideV2::Long).unwrap();
        let empty_short = canonical_empty_deficit_index_root_v2(DeficitSideV2::Short).unwrap();
        let (next, next_short) = verify_trader_deficit_index_batches_v2(
            &trader_updates,
            empty,
            empty_short,
            Some(&proof),
            None,
            bounds(),
            2,
        )
        .unwrap();
        assert_eq!(next.aggregate.leaf_count, 2);
        assert_eq!(next.aggregate.total_size_atoms, 2);
        assert_eq!(next_short, empty_short);

        let mut missing = proof.clone();
        missing.frontier.pop();
        assert_eq!(
            missing.verify_internal(empty, bounds(), 2),
            Err(ProtocolError::InvalidMerkleProof)
        );
        let mut trailing = proof.clone();
        trailing
            .frontier
            .push(DeficitIndexPathItemV2::CanonicalEmpty);
        assert_eq!(
            trailing.verify_internal(empty, bounds(), 2),
            Err(ProtocolError::InvalidMerkleProof)
        );
        let mut reordered = proof.clone();
        reordered.mutations.swap(0, 1);
        assert_eq!(
            reordered.verify_internal(empty, bounds(), 2),
            Err(ProtocolError::InvalidMerkleProof)
        );
        let mut substituted = proof.clone();
        substituted.mutations[0].trader_leaf.salt[0] ^= 1;
        assert_eq!(
            verify_trader_deficit_index_batch_projection_v2(
                &trader_updates,
                Some(&substituted),
                None,
                bounds(),
            ),
            Err(ProtocolError::InvalidMerkleProof)
        );
        let mut omitted = proof.clone();
        omitted.mutations.pop();
        assert_eq!(
            verify_trader_deficit_index_batch_projection_v2(
                &trader_updates,
                Some(&omitted),
                None,
                bounds(),
            ),
            Err(ProtocolError::InvalidMerkleProof)
        );
        assert_eq!(
            verify_trader_deficit_index_batch_projection_v2(&trader_updates, None, None, bounds(),),
            Err(ProtocolError::InvalidMerkleProof)
        );
        let mut wrong_root = empty;
        wrong_root.hash[0] ^= 1;
        assert_eq!(
            proof.verify_internal(wrong_root, bounds(), 2),
            Err(ProtocolError::InvalidMerkleProof)
        );

        // A leaf commitment replacement at one unchanged cut is represented
        // by exactly one adjacent Remove,Insert pair at the same index key.
        let old_same_cut = long_leaf_at_price(98, 303, 99);
        let mut new_same_cut = old_same_cut.clone();
        new_same_cut.account_nonce = 1;
        new_same_cut.salt = [100; 32];
        let replacement_mutations = vec![
            DeficitIndexBatchMutationV2 {
                kind: DeficitIndexMutationKindV2::Remove,
                trader_leaf: old_same_cut.clone(),
            },
            DeficitIndexBatchMutationV2 {
                kind: DeficitIndexMutationKindV2::Insert,
                trader_leaf: new_same_cut.clone(),
            },
        ];
        let derived = derive_and_validate_deficit_batch_mutations_v2(
            DeficitSideV2::Long,
            &replacement_mutations,
            bounds(),
        )
        .unwrap();
        let replacement = DeficitIndexBatchProofV2 {
            side: DeficitSideV2::Long,
            mutations: replacement_mutations,
            frontier: vec![
                DeficitIndexPathItemV2::CanonicalEmpty;
                deficit_batch_frontier_slot_count_v2(&derived).unwrap()
            ],
        };
        let old_root = single_line_deficit_root(
            DeficitIndexLeafV2::from_trader(&old_same_cut, bounds())
                .unwrap()
                .unwrap(),
        );
        let replacement_trader_update = TraderStateBatchLeafUpdateV2 {
            trader: old_same_cut.trader,
            old_leaf: Some(old_same_cut),
            new_leaf: Some(new_same_cut.clone()),
        };
        let (replaced_root, unchanged_short) = verify_trader_deficit_index_batches_v2(
            &[replacement_trader_update],
            old_root,
            empty_short,
            Some(&replacement),
            None,
            bounds(),
            2,
        )
        .unwrap();
        assert_eq!(
            replaced_root,
            single_line_deficit_root(
                DeficitIndexLeafV2::from_trader(&new_same_cut, bounds())
                    .unwrap()
                    .unwrap()
            )
        );
        assert_eq!(unchanged_short, empty_short);

        let mut duplicate_insert = replacement.clone();
        duplicate_insert.mutations[0].kind = DeficitIndexMutationKindV2::Insert;
        assert_eq!(
            duplicate_insert.verify_internal(old_root, bounds(), 2),
            Err(ProtocolError::DuplicateMerkleKey)
        );
    }

    #[test]
    fn compact_deficit_shared_frontier_has_exact_universal_wire_bound() {
        let mut mutations = Vec::with_capacity(MAX_DEFICIT_INDEX_UPDATES_PER_BATCH_V2);
        for seed in 1..=64u8 {
            let old = long_leaf_at_price(seed, 1_000 + u64::from(seed), seed);
            let mut new = long_leaf_at_price(seed, 10_000 + u64::from(seed), seed + 64);
            new.account_nonce = 1;
            mutations.push(DeficitIndexBatchMutationV2 {
                kind: DeficitIndexMutationKindV2::Remove,
                trader_leaf: old,
            });
            mutations.push(DeficitIndexBatchMutationV2 {
                kind: DeficitIndexMutationKindV2::Insert,
                trader_leaf: new,
            });
        }
        let mutations = sorted_deficit_batch_mutations(DeficitSideV2::Long, mutations);
        let derived = derive_and_validate_deficit_batch_mutations_v2(
            DeficitSideV2::Long,
            &mutations,
            bounds(),
        )
        .unwrap();
        let slots = deficit_batch_frontier_slot_count_v2(&derived).unwrap();
        assert!(slots <= MAX_DEFICIT_INDEX_SHARED_FRONTIER_ITEMS_V2);
        let occupied = DeficitRangeAggregateV2 {
            leaf_count: 1,
            total_size_atoms: 1,
            total_intercept_numerator: Int256V2::ZERO,
        };
        let frontier = (0..slots)
            .map(|index| {
                DeficitIndexPathItemV2::Occupied(DeficitIndexNodeV2 {
                    hash: tagged_hash("ECX/test/deficit-shared-occupied", &index.to_be_bytes()),
                    aggregate: occupied,
                })
            })
            .collect::<Vec<_>>();
        let proof = DeficitIndexBatchProofV2 {
            side: DeficitSideV2::Long,
            mutations,
            frontier,
        };
        let bytes = proof.canonical_bytes_checked(bounds()).unwrap();
        assert_eq!(slots, 35_567);
        assert_eq!(bytes.len(), 3_508_998);
        assert!(bytes.len() < MAX_SHARED_DEFICIT_INDEX_UPDATE_BATCH_BYTES_V2);
        let (old, expected_new) =
            compute_deficit_batch_subtree_v2(proof.side, &derived, &proof.frontier, bounds())
                .unwrap();
        assert_eq!(
            proof
                .verify_internal(
                    DeficitIndexRootV2::from_node(proof.side, old),
                    bounds(),
                    MAX_DEFICIT_INDEX_UPDATES_PER_BATCH_V2,
                )
                .unwrap(),
            DeficitIndexRootV2::from_node(proof.side, expected_new)
        );

        let mutation_bytes = DeficitIndexBatchMutationV2 {
            kind: DeficitIndexMutationKindV2::Insert,
            trader_leaf: long_leaf_at_price(120, 1, 121),
        }
        .canonical_bytes()
        .len();
        let node_bytes = DeficitIndexPathItemV2::Occupied(DeficitIndexNodeV2 {
            hash: [1; 32],
            aggregate: occupied,
        })
        .canonical_bytes()
        .len();
        assert_eq!(mutation_bytes, 183);
        assert_eq!(node_bytes, 98);
        let universal_wire_maximum = 1usize
            + 1
            + 2
            + MAX_DEFICIT_INDEX_UPDATES_PER_BATCH_V2 * mutation_bytes
            + 4
            + MAX_DEFICIT_INDEX_SHARED_FRONTIER_ITEMS_V2 * node_bytes;
        assert_eq!(universal_wire_maximum, 6_458_504);
        assert!(universal_wire_maximum < MAX_SHARED_DEFICIT_INDEX_UPDATE_BATCH_BYTES_V2);
    }

    #[test]
    fn deficit_signed_cuts_are_numeric_strict_and_funding_stable() {
        assert_eq!(i256(-5).floor_div_u64(2).unwrap(), i256(-3));
        assert_eq!(i256(-5).ceil_div_u64(2).unwrap(), i256(-2));
        assert_eq!(i256(5).floor_div_u64(2).unwrap(), i256(2));
        assert_eq!(i256(5).ceil_div_u64(2).unwrap(), i256(3));
        let ordered =
            [-2, -1, 0, 1, 2].map(|value| signed_numeric_order_key_v2(i256(value)).unwrap());
        assert!(ordered.windows(2).all(|pair| pair[0] < pair[1]));

        let negative_long = deficit_line(DeficitSideV2::Long, 43, -5, 2);
        let negative_short = deficit_line(DeficitSideV2::Short, 44, -5, 2);
        assert_eq!(negative_long.cut_q_numerator, i256(-2));
        assert_eq!(negative_short.cut_q_numerator, i256(-3));

        let mut same_cut = vec![
            deficit_line(DeficitSideV2::Long, 45, 10, 2),
            deficit_line(DeficitSideV2::Long, 46, 10, 2),
        ];
        same_cut.sort_by_key(|line| line.key());
        assert_eq!(same_cut[0].cut_q_numerator, i256(5));
        assert_eq!(same_cut[1].cut_q_numerator, i256(5));
        assert_eq!(
            aggregate_eligible_deficit_lines_v2(DeficitSideV2::Long, i256(5), &same_cut, bounds(),)
                .unwrap(),
            DeficitRangeAggregateV2::ZERO
        );
        let eligible =
            aggregate_eligible_deficit_lines_v2(DeficitSideV2::Long, i256(4), &same_cut, bounds())
                .unwrap();
        assert_eq!(eligible.leaf_count, 2);
        assert_eq!(
            eligible
                .deficit_numerator(DeficitSideV2::Long, i256(4), bounds())
                .unwrap(),
            Uint256V2::from_u64(4)
        );
        let mut reversed = same_cut.clone();
        reversed.reverse();
        assert_eq!(
            aggregate_eligible_deficit_lines_v2(DeficitSideV2::Long, i256(4), &reversed, bounds(),),
            Err(ProtocolError::InvalidMerkleProof)
        );
        let duplicated = vec![same_cut[0], same_cut[0]];
        assert_eq!(
            aggregate_eligible_deficit_lines_v2(
                DeficitSideV2::Long,
                i256(4),
                &duplicated,
                bounds(),
            ),
            Err(ProtocolError::InvalidMerkleProof)
        );

        let q_bound_magnitude = bounds().maximum_reachable_abs_q_numerator().unwrap();
        let q_bound =
            Int256V2::from_sign_and_magnitude(false, q_bound_magnitude.to_be_bytes()).unwrap();
        let outside_q_magnitude = q_bound_magnitude
            .checked_add(Uint256V2::from_u64(1))
            .unwrap();
        let outside_positive =
            Int256V2::from_sign_and_magnitude(false, outside_q_magnitude.to_be_bytes()).unwrap();
        let outside_negative = outside_positive.checked_neg().unwrap();
        let always_long = DeficitIndexLeafV2 {
            cut_q_numerator: outside_positive,
            intercept_numerator: outside_positive,
            ..deficit_line(DeficitSideV2::Long, 47, 1, 1)
        };
        let always_short = DeficitIndexLeafV2 {
            cut_q_numerator: outside_negative,
            intercept_numerator: outside_negative,
            ..deficit_line(DeficitSideV2::Short, 48, 1, 1)
        };
        let never_long = DeficitIndexLeafV2 {
            cut_q_numerator: outside_negative,
            intercept_numerator: outside_negative,
            ..deficit_line(DeficitSideV2::Long, 53, 1, 1)
        };
        let never_short = DeficitIndexLeafV2 {
            cut_q_numerator: outside_positive,
            intercept_numerator: outside_positive,
            ..deficit_line(DeficitSideV2::Short, 54, 1, 1)
        };
        always_long.validate(bounds()).unwrap();
        always_short.validate(bounds()).unwrap();
        never_long.validate(bounds()).unwrap();
        never_short.validate(bounds()).unwrap();
        assert_eq!(
            aggregate_eligible_deficit_lines_v2(
                DeficitSideV2::Long,
                q_bound,
                &[always_long],
                bounds(),
            )
            .unwrap()
            .leaf_count,
            1
        );
        assert_eq!(
            aggregate_eligible_deficit_lines_v2(
                DeficitSideV2::Short,
                q_bound.checked_neg().unwrap(),
                &[always_short],
                bounds(),
            )
            .unwrap()
            .leaf_count,
            1
        );
        assert_eq!(
            aggregate_eligible_deficit_lines_v2(
                DeficitSideV2::Long,
                q_bound.checked_neg().unwrap(),
                &[never_long],
                bounds(),
            )
            .unwrap(),
            DeficitRangeAggregateV2::ZERO
        );
        assert_eq!(
            aggregate_eligible_deficit_lines_v2(
                DeficitSideV2::Short,
                q_bound,
                &[never_short],
                bounds(),
            )
            .unwrap(),
            DeficitRangeAggregateV2::ZERO
        );

        // Funding changes Q, not any leaf key.
        let q_first = price_funding_q_numerator_v2(100, 7, bounds()).unwrap();
        let q_second = price_funding_q_numerator_v2(100, 19, bounds()).unwrap();
        assert_eq!(q_first.checked_sub(q_second).unwrap(), i256(12));
        assert_eq!(same_cut[0].key(), same_cut[0].key());
    }

    #[test]
    fn deficit_aggregate_matches_naive_lines_across_deterministic_random_vectors() {
        let mut state = 0x8d26_5f47_b1c3_09e7u64;
        let mut longs = Vec::new();
        let mut shorts = Vec::new();
        for index in 0..12u8 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let intercept = i128::from(state % 401) - 200;
            let size = state.rotate_left(17) % 9 + 1;
            longs.push(deficit_line(
                DeficitSideV2::Long,
                60 + index,
                intercept,
                size,
            ));
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let intercept = i128::from(state % 401) - 200;
            let size = state.rotate_left(17) % 9 + 1;
            shorts.push(deficit_line(
                DeficitSideV2::Short,
                80 + index,
                intercept,
                size,
            ));
        }
        longs.sort_by_key(|line| line.key());
        shorts.sort_by_key(|line| line.key());
        for q in -50i128..=50 {
            let q_numerator = i256(q);
            let long_aggregate = aggregate_eligible_deficit_lines_v2(
                DeficitSideV2::Long,
                q_numerator,
                &longs,
                bounds(),
            )
            .unwrap();
            let short_aggregate = aggregate_eligible_deficit_lines_v2(
                DeficitSideV2::Short,
                q_numerator,
                &shorts,
                bounds(),
            )
            .unwrap();
            let actual_long = long_aggregate
                .deficit_numerator(DeficitSideV2::Long, q_numerator, bounds())
                .unwrap()
                .try_to_u128()
                .unwrap();
            let actual_short = short_aggregate
                .deficit_numerator(DeficitSideV2::Short, q_numerator, bounds())
                .unwrap()
                .try_to_u128()
                .unwrap();
            let naive_long = longs
                .iter()
                .map(|line| {
                    let value = line.intercept_numerator.try_to_i128().unwrap()
                        - q * i128::from(line.size_atoms);
                    value.max(0) as u128
                })
                .sum::<u128>();
            let naive_short = shorts
                .iter()
                .map(|line| {
                    let value = q * i128::from(line.size_atoms)
                        - line.intercept_numerator.try_to_i128().unwrap();
                    value.max(0) as u128
                })
                .sum::<u128>();
            assert_eq!(actual_long, naive_long);
            assert_eq!(actual_short, naive_short);
        }
    }

    #[test]
    fn deficit_lines_bind_each_typed_trader_update_and_round_portfolio_once() {
        let old = flat_leaf(49);
        let mut new = old.clone();
        new.position_size_atoms = 2;
        new.signed_cost_basis_numerator = i256(10 * i128::from(FUNDING_INDEX_DENOMINATOR_V2));
        new.last_funding_index_numerator = 3;
        let trader_update = TraderStateBatchLeafUpdateV2 {
            trader: old.trader,
            old_leaf: Some(old),
            new_leaf: Some(new.clone()),
        };
        let link = TraderDeficitUpdateLinkV2 {
            trader: new.trader,
            old_line: None,
            new_line: DeficitIndexLeafV2::from_trader(&new, bounds()).unwrap(),
        };
        verify_trader_deficit_update_links_v2(
            std::slice::from_ref(&trader_update),
            std::slice::from_ref(&link),
            bounds(),
        )
        .unwrap();
        let mut swapped_side = link.new_line.unwrap();
        swapped_side.side = DeficitSideV2::Short;
        swapped_side.cut_q_numerator = swapped_side
            .intercept_numerator
            .floor_div_u64(swapped_side.size_atoms)
            .unwrap();
        swapped_side.validate(bounds()).unwrap();
        assert_eq!(
            swapped_side.verify_against_trader(&new, bounds()),
            Err(ProtocolError::InvalidMerkleProof)
        );
        let mut substituted = link.clone();
        substituted
            .new_line
            .as_mut()
            .unwrap()
            .trader_leaf_commitment[0] ^= 1;
        assert_eq!(
            verify_trader_deficit_update_links_v2(
                std::slice::from_ref(&trader_update),
                &[substituted],
                bounds()
            ),
            Err(ProtocolError::InvalidMerkleProof)
        );
        assert_eq!(
            verify_trader_deficit_update_links_v2(&[trader_update], &[], bounds()),
            Err(ProtocolError::InvalidMerkleProof)
        );

        let long = deficit_line(DeficitSideV2::Long, 50, 1, 1);
        let short = deficit_line(DeficitSideV2::Short, 51, -1, 1);
        let long_selected = aggregate_eligible_deficit_lines_v2(
            DeficitSideV2::Long,
            Int256V2::ZERO,
            &[long],
            bounds(),
        )
        .unwrap();
        let short_selected = aggregate_eligible_deficit_lines_v2(
            DeficitSideV2::Short,
            Int256V2::ZERO,
            &[short],
            bounds(),
        )
        .unwrap();
        let mut flat_debt = flat_leaf(52);
        flat_debt.collateral_atoms = 0;
        flat_debt.cash_residual_numerator =
            -i64::try_from(EXACT_ACCOUNTING_DENOMINATOR_V2 - 2).unwrap();
        let flat_numerator = flat_debt
            .aggregate(bounds())
            .unwrap()
            .flat_negative_exact_cash_numerator;
        // 1 long + 1 short + (D-2) flat = exactly D. Rounding once gives one
        // atom; independently rounding each account would incorrectly give 3.
        assert_eq!(
            portfolio_deficit_atoms_v2(
                long_selected,
                short_selected,
                flat_numerator,
                Int256V2::ZERO,
                bounds(),
            )
            .unwrap(),
            Uint256V2::from_u64(1)
        );
        // The same authenticated flat debt is added once at either endpoint.
        assert_eq!(
            portfolio_deficit_atoms_v2(
                DeficitRangeAggregateV2::ZERO,
                DeficitRangeAggregateV2::ZERO,
                flat_numerator,
                i256(123),
                bounds(),
            )
            .unwrap(),
            Uint256V2::from_u64(1)
        );
    }

    #[test]
    fn partial_close_retains_cost_remainder_and_crossing_is_exact() {
        let mut leaf = flat_leaf(7);
        leaf.collateral_atoms = 1;
        leaf.position_size_atoms = 3;
        leaf.signed_cost_basis_numerator = i256(10 * i128::from(FUNDING_INDEX_DENOMINATOR_V2));
        leaf.last_funding_index_numerator = 0;
        leaf.validate(bounds()).unwrap();

        let realized = leaf.apply_trade_exact(-1, 5, 0, bounds()).unwrap();
        assert_eq!(realized, i256(1_666_667));
        assert_eq!(leaf.position_size_atoms, 2);
        // 10_000_000 * 1 / 3 truncates to 3_333_333, leaving the
        // indivisible unit in the still-open cost 6_666_667.
        assert_eq!(leaf.signed_cost_basis_numerator, i256(6_666_667));
        assert_eq!(leaf.cash_residual_numerator, 1_666_667);

        let realized = leaf.apply_trade_exact(-3, 4, 0, bounds()).unwrap();
        assert_eq!(realized, i256(1_333_333));
        assert_eq!(leaf.position_size_atoms, -1);
        assert_eq!(leaf.signed_cost_basis_numerator, i256(-4_000_000));
        assert_eq!(leaf.cash_residual_numerator, 3_000_000);
    }

    #[test]
    fn lazy_funding_uses_exact_residual_and_is_transactional_on_failure() {
        let mut long = flat_leaf(8);
        long.collateral_atoms = 2;
        long.position_size_atoms = 3;
        long.signed_cost_basis_numerator =
            i256(3 * i128::from(PRICE_SCALE) * i128::from(FUNDING_INDEX_DENOMINATOR_V2));
        long.last_funding_index_numerator = 7;
        long.settle_lazy_funding(10, bounds()).unwrap();
        assert_eq!(long.last_funding_index_numerator, 10);
        assert_eq!(
            long.exact_cash_numerator(bounds()).unwrap(),
            i256(2 * i128::from(EXACT_ACCOUNTING_DENOMINATOR_V2) - 9)
        );

        let mut negative = flat_leaf(9);
        negative.collateral_atoms = 0;
        negative.position_size_atoms = 1;
        negative.signed_cost_basis_numerator =
            i256(i128::from(PRICE_SCALE) * i128::from(FUNDING_INDEX_DENOMINATOR_V2));
        negative.settle_lazy_funding(1, bounds()).unwrap();
        assert_eq!(negative.collateral_atoms, 0);
        assert_eq!(negative.cash_residual_numerator, -1);
        assert_eq!(negative.exact_cash_numerator(bounds()).unwrap(), i256(-1));
        let before = negative.clone();
        assert_eq!(
            negative.settle_lazy_funding(i128::MAX, bounds()),
            Err(ProtocolError::InvalidBondState)
        );
        assert_eq!(negative, before);
    }

    #[test]
    fn funding_index_units_match_legacy_epoch_and_varying_marks_zero_sum() {
        let first = advance_exact_funding_index_v2(0, 250_000_003, 3_333).unwrap();
        let second = advance_exact_funding_index_v2(first, 199_999_999, -2_001).unwrap();
        assert_eq!(first, 250_000_003i128 * 3_333);
        assert_eq!(second, first - 199_999_999i128 * 2_001);

        let mut long = flat_leaf(14);
        long.position_size_atoms = 7;
        long.signed_cost_basis_numerator =
            i256(7 * 200_000_000i128 * i128::from(FUNDING_INDEX_DENOMINATOR_V2));
        let mut short = flat_leaf(15);
        short.position_size_atoms = -7;
        short.signed_cost_basis_numerator =
            i256(-7 * 200_000_000i128 * i128::from(FUNDING_INDEX_DENOMINATOR_V2));
        let before = long
            .exact_cash_numerator(bounds())
            .unwrap()
            .checked_add(short.exact_cash_numerator(bounds()).unwrap())
            .unwrap();
        long.settle_lazy_funding(first, bounds()).unwrap();
        short.settle_lazy_funding(first, bounds()).unwrap();
        long.settle_lazy_funding(second, bounds()).unwrap();
        short.settle_lazy_funding(second, bounds()).unwrap();
        let after = long
            .exact_cash_numerator(bounds())
            .unwrap()
            .checked_add(short.exact_cash_numerator(bounds()).unwrap())
            .unwrap();
        assert_eq!(after, before);

        let base_epoch_long = -(7i128 * 250_000_003 * 3_333);
        assert_eq!(
            long.exact_cash_numerator(bounds())
                .unwrap()
                .checked_sub(i256(100 * i128::from(EXACT_ACCOUNTING_DENOMINATOR_V2)))
                .unwrap(),
            i256(base_epoch_long + 7 * 199_999_999i128 * 2_001)
        );
    }

    #[test]
    fn funding_lifetime_bound_covers_full_u64_mtp_and_rejects_next_value() {
        let maximum = maximum_reachable_abs_funding_index_v2().unwrap();
        assert!(maximum < i128::MAX);
        validate_exact_funding_index_v2(maximum).unwrap();
        validate_exact_funding_index_v2(-maximum).unwrap();
        assert_eq!(
            validate_exact_funding_index_v2(maximum + 1),
            Err(ProtocolError::ArithmeticOverflow)
        );
        assert_eq!(
            advance_exact_funding_index_v2(maximum, u64::MAX, 1),
            Err(ProtocolError::ArithmeticOverflow)
        );
    }

    #[test]
    fn ecx_tree_trade_commits_both_cash_updates_or_neither() {
        use crate::ecx_cash_account_v1::*;
        use crate::ecx_collateral::EcxCollateralAtoms;
        // Independently assemble the two present branches. Opaque siblings
        // test membership composition, not completeness of a funded ledger.
        fn pair_paths(a: Hash32, ah: Hash32, b: Hash32, bh: Hash32) -> (Vec<Hash32>, Vec<Hash32>) {
            let split = (0..256).find(|&i| ((a[i / 8] ^ b[i / 8]) >> (7 - i % 8)) & 1 != 0).unwrap();
            let join = 255 - split;
            let mut ap = vec![[9; 32]; 256];
            let mut bp = ap.clone();
            let mut an = ah; let mut bn = bh;
            let parent = |key: Hash32, node: Hash32, height: usize| {
                let bit = 255 - height;
                let mut bytes = vec![1];
                bytes.extend_from_slice(&((height + 1) as u16).to_be_bytes());
                if (key[bit / 8] >> (7 - bit % 8)) & 1 == 0 {
                    bytes.extend_from_slice(&node); bytes.extend_from_slice(&[9; 32]);
                } else {
                    bytes.extend_from_slice(&[9; 32]); bytes.extend_from_slice(&node);
                }
                tagged_hash("ECX/ecx-account-tree-node/v1", &bytes)
            };
            for height in 0..join { an = parent(a, an, height); bn = parent(b, bn, height); }
            ap[join] = bn; bp[join] = an;
            (ap, bp)
        }
        let domain = EcxAccountDomainV1 { chain_id: [1; 32], market: crate::types::ECX_USDD_MARKET,
            configuration_hash: [2; 32], collateral_asset: [3; 32] };
        let mut position = flat_leaf(16); position.collateral_atoms = 0;
        let mut clearing = flat_leaf(17); clearing.collateral_atoms = 0;
        let cash = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(100_000_000));
        let entry = Price::new(30 * PRICE_SCALE).unwrap();
        let exit = Price::new(60 * PRICE_SCALE).unwrap();
        position.apply_trade_for_ecx_settlement(100_000_000, entry.get(), 0, bounds()).unwrap();
        let intended = stage_account_trade(&position, &cash, &cash, -100_000_000, exit, exit, 0, bounds()).unwrap();
        let ah = ecx_account_commitment(domain, &position, &cash, bounds()).unwrap();
        let bh = ecx_account_commitment(domain, &clearing, &cash, bounds()).unwrap();
        let (ap, old_bp) = pair_paths(position.key(), ah, clearing.key(), bh);
        let source = ecx_account_root(domain, &position, &cash, bounds(), &ap).unwrap();
        assert_eq!(source, ecx_account_root(domain, &clearing, &cash, bounds(), &old_bp).unwrap());
        let new_ah = ecx_account_commitment(domain, &intended.position, &intended.trader_cash, bounds()).unwrap();
        let (_, bp) = pair_paths(position.key(), new_ah, clearing.key(), bh);
        let run = |path: &[Hash32], clearing_key| stage_ecx_tree_trade(source, domain, clearing_key,
            EcxAccountOpeningV1 { position: &position, cash: &cash, siblings: &ap },
            EcxAccountOpeningV1 { position: &clearing, cash: &cash, siblings: path },
            -100_000_000, exit, exit, 0, bounds());
        let result = run(&bp, clearing.trader).unwrap();
        assert_eq!(result.settlement, intended);
        assert_eq!(result.settlement.trader_cash.balance().0, 150_000_000);
        assert_eq!(result.settlement.clearing_cash.balance().0, 50_000_000);
        let new_bh = ecx_account_commitment(domain, &clearing, &intended.clearing_cash, bounds()).unwrap();
        let (final_ap, final_bp) = pair_paths(position.key(), new_ah, clearing.key(), new_bh);
        assert_eq!(result.root, ecx_account_root(domain, &intended.position, &intended.trader_cash, bounds(), &final_ap).unwrap());
        assert_eq!(result.root, ecx_account_root(domain, &clearing, &intended.clearing_cash, bounds(), &final_bp).unwrap());
        assert!(run(&old_bp, clearing.trader).is_err());
        assert!(run(&bp, position.trader).is_err());
        assert_eq!(cash.balance().0, 100_000_000);
        assert_eq!(position.position_size_atoms, 100_000_000);
    }

    #[test]
    fn ecx_account_membership_replacement_rejects_stale_and_substituted_paths() {
        use crate::ecx_cash_account_v1::{ecx_account_root, replace_ecx_account_leaf, EcxAccountDomainV1, EcxCashAccountV1};
        use crate::ecx_collateral::EcxCollateralAtoms;
        let domain = EcxAccountDomainV1 { chain_id: [1; 32], market: crate::types::ECX_USDD_MARKET,
            configuration_hash: [2; 32], collateral_asset: [3; 32] };
        let mut position = flat_leaf(16);
        position.collateral_atoms = 0;
        position.cash_residual_numerator = 0;
        let cash = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(100));
        let next_cash = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(101));
        let path = vec![[9; 32]; 256];
        let root = ecx_account_root(domain, &position, &cash, bounds(), &path).unwrap();
        let next = replace_ecx_account_leaf(root, domain, &position, &cash, &position, &next_cash, bounds(), &path).unwrap();
        assert_ne!(root, next);
        assert_eq!(next, ecx_account_root(domain, &position, &next_cash, bounds(), &path).unwrap());
        assert!(replace_ecx_account_leaf(next, domain, &position, &cash, &position, &next_cash, bounds(), &path).is_err());
        assert!(ecx_account_root(domain, &position, &cash, bounds(), &path[..255]).is_err());
        let mut longer = path.clone(); longer.push([9; 32]);
        assert!(ecx_account_root(domain, &position, &cash, bounds(), &longer).is_err());
        for height in [0, 127, 255] {
            let mut changed = path.clone(); changed[height][0] ^= 1;
            assert!(replace_ecx_account_leaf(root, domain, &position, &cash, &position, &next_cash, bounds(), &changed).is_err());
        }
        let mut other = position.clone(); other.trader = flat_leaf(17).trader;
        assert!(replace_ecx_account_leaf(root, domain, &position, &cash, &other, &next_cash, bounds(), &path).is_err());
        let wrong_domain = EcxAccountDomainV1 { collateral_asset: [4; 32], ..domain };
        assert!(replace_ecx_account_leaf(root, wrong_domain, &position, &cash, &position, &next_cash, bounds(), &path).is_err());
    }

    #[test]
    fn ecx_account_leaf_binds_domain_owner_position_and_cash() {
        use crate::ecx_cash_account_v1::{ecx_account_commitment, EcxAccountDomainV1, EcxCashAccountV1};
        use crate::ecx_collateral::EcxCollateralAtoms;
        let domain = EcxAccountDomainV1 {
            chain_id: [1; 32], market: crate::types::ECX_USDD_MARKET,
            configuration_hash: [2; 32], collateral_asset: [3; 32],
        };
        let mut position = flat_leaf(16);
        position.collateral_atoms = 0;
        position.cash_residual_numerator = 0;
        let cash = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(100));
        let expected = ecx_account_commitment(domain, &position, &cash, bounds()).unwrap();
        for changed in [
            EcxAccountDomainV1 { chain_id: [4; 32], ..domain },
            EcxAccountDomainV1 { configuration_hash: [4; 32], ..domain },
            EcxAccountDomainV1 { collateral_asset: [4; 32], ..domain },
        ] {
            assert_ne!(ecx_account_commitment(changed, &position, &cash, bounds()).unwrap(), expected);
        }
        for changed in [
            EcxAccountDomainV1 { chain_id: [0; 32], ..domain },
            EcxAccountDomainV1 { configuration_hash: [0; 32], ..domain },
            EcxAccountDomainV1 { collateral_asset: [0; 32], ..domain },
            EcxAccountDomainV1 { market: crate::types::MarketId([0; 16]), ..domain },
        ] {
            assert!(ecx_account_commitment(changed, &position, &cash, bounds()).is_err());
        }
        let mut changed = position.clone();
        changed.trader = flat_leaf(17).trader;
        assert_ne!(ecx_account_commitment(domain, &changed, &cash, bounds()).unwrap(), expected);
        changed = position.clone();
        changed.account_nonce += 1;
        assert_ne!(ecx_account_commitment(domain, &changed, &cash, bounds()).unwrap(), expected);
        let other_cash = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(101));
        assert_ne!(ecx_account_commitment(domain, &position, &other_cash, bounds()).unwrap(), expected);
        changed = position.clone();
        changed.collateral_atoms = 1;
        assert!(ecx_account_commitment(domain, &changed, &cash, bounds()).is_err());
        changed.collateral_atoms = 0;
        changed.cash_residual_numerator = 1;
        assert!(ecx_account_commitment(domain, &changed, &cash, bounds()).is_err());
        let restored = EcxCashAccountV1::from_bytes(&cash.canonical_bytes()).unwrap();
        assert_eq!(ecx_account_commitment(domain, &position, &restored, bounds()).unwrap(), expected);
    }

    #[test]
    fn ecx_cash_state_survives_funding_restart_and_close() {
        use crate::ecx_cash_account_v1::{EcxCashAccountV1, stage_account_trade, stage_account_funding};
        use crate::ecx_collateral::EcxCollateralAtoms;
        let mut position = flat_leaf(16);
        position.collateral_atoms = 0;
        position.cash_residual_numerator = 0;
        let cash = EcxCashAccountV1::from_funded_balance(EcxCollateralAtoms(100_000_000));
        let entry = Price::new(30 * PRICE_SCALE).unwrap();
        let mark = Price::new(7 * PRICE_SCALE).unwrap();
        let open = stage_account_trade(&position, &cash, &cash, 1, entry, entry, 0, bounds()).unwrap();
        let funded = stage_account_funding(&open.position, &open.trader_cash, &open.clearing_cash,
            mark, 1, bounds()).unwrap();
        assert_eq!(funded.trader_cash.outstanding_claims().len(), 1);
        let trader = EcxCashAccountV1::from_bytes(&funded.trader_cash.canonical_bytes()).unwrap();
        let clearing = EcxCashAccountV1::from_bytes(&funded.clearing_cash.canonical_bytes()).unwrap();
        let repeated = stage_account_funding(&funded.position, &trader, &clearing, mark, 1, bounds()).unwrap();
        assert_eq!(repeated, funded);
        let closed = stage_account_trade(&repeated.position, &trader, &clearing,
            -1, entry, entry, 1, bounds()).unwrap();
        assert_eq!(closed.position.position_size_atoms, 0);
        // Closing a flat-price position cannot erase the earlier funding claim.
        assert_eq!(closed.trader_cash, trader);
        assert_eq!(closed.clearing_cash, clearing);
        assert_eq!(closed.position.collateral_atoms, 0);
        assert_eq!(closed.position.cash_residual_numerator, 0);
        // Risk must retain the negative funding fraction even after closure.
        let (lower, upper) = trader.equity_bounds(&closed.position, 1_000_000,
            mark, 1, bounds()).unwrap();
        let whole_only = crate::ecx_collateral::ecx_trader_equity_numerator(
            &closed.position, Int256V2::from_u128(u128::from(trader.balance().0) * 1_000_000),
            1_000_000, mark, 1, bounds()).unwrap();
        assert!(lower < whole_only);
        assert_eq!(upper, whole_only);
    }

    #[test]
    fn ecx_staging_keeps_position_and_funding_unchanged_on_failed_payment() {
        use crate::ecx_collateral::{EcxCollateralAtoms, stage_ecx_trade, stage_ecx_funding};
        let mut position = flat_leaf(16);
        position.collateral_atoms = 0;
        position.cash_residual_numerator = 0;
        position.apply_trade_for_ecx_settlement(100_000_000, 30 * PRICE_SCALE, 0, bounds()).unwrap();
        let original = position.clone();
        let price = Price::new(60 * PRICE_SCALE).unwrap();
        assert_eq!(stage_ecx_trade(&position, EcxCollateralAtoms(100_000_000),
            EcxCollateralAtoms(0), -100_000_000, price, price, 0, bounds()),
            Err(ProtocolError::InsufficientCollateral));
        assert_eq!(position, original);
        let closed = stage_ecx_trade(&position, EcxCollateralAtoms(100_000_000),
            EcxCollateralAtoms(50_000_000), -100_000_000, price, price, 0, bounds()).unwrap();
        assert_eq!(closed.position.position_size_atoms, 0);
        assert_eq!(closed.payment.first_balance.0, 150_000_000);
        assert_eq!(closed.payment.second_balance.0, 0);
        let index = i128::from(30 * PRICE_SCALE) * 10_000;
        let mark = Price::new(30 * PRICE_SCALE).unwrap();
        assert_eq!(stage_ecx_funding(&position, EcxCollateralAtoms(0),
            EcxCollateralAtoms(0), mark, index, bounds()), Err(ProtocolError::InsufficientCollateral));
        assert_eq!(position, original);
        let funded = stage_ecx_funding(&position, EcxCollateralAtoms(1_000_000),
            EcxCollateralAtoms(0), mark, index, bounds()).unwrap();
        assert_eq!(funded.payment.first_balance.0, 0);
        assert_eq!(funded.payment.second_balance.0, 1_000_000);
        let repeated = stage_ecx_funding(&funded.position, funded.payment.first_balance,
            funded.payment.second_balance, mark, index, bounds()).unwrap();
        assert_eq!(repeated.payment.first_balance, funded.payment.first_balance);
        assert_eq!(repeated.payment.second_balance, funded.payment.second_balance);
        assert_eq!(repeated.payment.first_residual, Int256V2::ZERO);
        assert_eq!(position, original);
    }

    #[test]
    fn ecx_funding_and_close_pay_only_ecx() {
        use crate::ecx_collateral::{EcxCollateralAtoms, settle_opposing_ecx_pnl};
        for exit in [15, 60] {
            let mut long = flat_leaf(16);
            let mut short = flat_leaf(17);
            for leaf in [&mut long, &mut short] {
                leaf.collateral_atoms = 0;
                leaf.cash_residual_numerator = 0;
            }
            long.apply_trade_for_ecx_settlement(100_000_000, 30 * PRICE_SCALE, 0, bounds()).unwrap();
            short.apply_trade_for_ecx_settlement(-100_000_000, 30 * PRICE_SCALE, 0, bounds()).unwrap();
            // One percent funding: long pays 0.01 ECX at the funding mark.
            let index = i128::from(30 * PRICE_SCALE) * 10_000;
            let funding = long.settle_lazy_funding_for_ecx(index, bounds()).unwrap();
            assert_eq!(short.settle_lazy_funding_for_ecx(index, bounds()).unwrap(), funding.checked_neg().unwrap());
            let paid = settle_opposing_ecx_pnl(EcxCollateralAtoms(200_000_000),
                EcxCollateralAtoms(200_000_000), funding, Price::new(30 * PRICE_SCALE).unwrap()).unwrap();
            assert_eq!(paid.first_balance, EcxCollateralAtoms(199_000_000));
            assert_eq!(paid.second_balance, EcxCollateralAtoms(201_000_000));
            assert_eq!(paid.first_residual, Int256V2::ZERO);
            assert_eq!(long.settle_lazy_funding_for_ecx(index, bounds()).unwrap(), Int256V2::ZERO);
            let pnl = long.apply_trade_for_ecx_settlement(-100_000_000, exit * PRICE_SCALE, index, bounds()).unwrap();
            assert_eq!(short.apply_trade_for_ecx_settlement(100_000_000, exit * PRICE_SCALE, index, bounds()).unwrap(), pnl.checked_neg().unwrap());
            let closed = settle_opposing_ecx_pnl(paid.first_balance, paid.second_balance,
                pnl, Price::new(exit * PRICE_SCALE).unwrap()).unwrap();
            assert_eq!(closed.first_balance.0, if exit == 60 { 249_000_000 } else { 99_000_000 });
            assert_eq!(closed.first_balance.0 + closed.second_balance.0, 400_000_000);
            assert_eq!(closed.first_residual, Int256V2::ZERO);
            for leaf in [&long, &short] {
                assert_eq!(leaf.position_size_atoms, 0);
                assert_eq!(leaf.collateral_atoms, 0);
                assert_eq!(leaf.cash_residual_numerator, 0);
            }
            assert_eq!(closed.first_balance.checked_withdraw(closed.first_balance.0).unwrap(), EcxCollateralAtoms(0));
            assert!(settle_opposing_ecx_pnl(EcxCollateralAtoms(0), EcxCollateralAtoms(0),
                pnl, Price::new(exit * PRICE_SCALE).unwrap()).is_err());
        }
    }

    #[test]
    fn ecx_equity_matches_independent_integer_formula_with_sub_atoms() {
        use crate::ecx_collateral::ecx_trader_equity_numerator;
        for size in [-100_000_000, 100_000_000] {
            let mut position = flat_leaf(16);
            position.collateral_atoms = 0;
            position.cash_residual_numerator = 0;
            position.apply_trade_for_ecx_settlement(size, 30 * PRICE_SCALE, 77, bounds()).unwrap();
            for scale in [1u64, 1_000_000] {
                for cash in [-100_000_001i128, -1, 0, 1, 200_000_001] {
                    for mark in [15 * PRICE_SCALE, 30 * PRICE_SCALE, 60 * PRICE_SCALE] {
                        let expected = BigInt::from(cash) * BigInt::from(mark)
                            * BigInt::from(FUNDING_INDEX_DENOMINATOR_V2)
                            + (BigInt::from(size) * BigInt::from(mark)
                                * BigInt::from(FUNDING_INDEX_DENOMINATOR_V2)
                                - bigint_from_int256(position.signed_cost_basis_numerator)
                                - BigInt::from(size) * BigInt::from(109 - 77))
                                * BigInt::from(scale);
                        assert_eq!(bigint_from_int256(ecx_trader_equity_numerator(
                            &position, i256(cash), scale, Price::new(mark).unwrap(), 109, bounds(),
                        ).unwrap()), expected);
                    }
                }
            }
        }
    }

    #[test]
    fn ecx_collateral_changes_short_exposure_and_preserves_margin_rounding() {
        use crate::ecx_collateral::{ecx_trader_equity_numerator, is_ecx_trader_liquidatable};
        let mut short = flat_leaf(16);
        short.collateral_atoms = 0;
        short.cash_residual_numerator = 0;
        short.apply_trade_for_ecx_settlement(-100_000_000, 30 * PRICE_SCALE, 0, bounds()).unwrap();
        let cash = i256(200_000_000);
        let equity = |p| ecx_trader_equity_numerator(&short, cash, 1, Price::new(p).unwrap(), 0, bounds()).unwrap();
        // Two ECX of collateral and a one-ECX short: total exposure is LONG
        // one ECX. Reusing the USDD short-side adverse endpoint would be wrong.
        assert!(equity(15 * PRICE_SCALE) < equity(60 * PRICE_SCALE));
        for mark in [1, 101, 15 * PRICE_SCALE, 30 * PRICE_SCALE, 60 * PRICE_SCALE] {
            for balance in [0i128, 1, 100_000_000] {
                let mut marked_quote = short.clone();
                marked_quote.apply_exact_cash_delta_numerator(
                    i256(balance).checked_mul_u64(mark).unwrap()
                        .checked_mul_u64(FUNDING_INDEX_DENOMINATOR_V2).unwrap(), bounds(),
                ).unwrap();
                assert_eq!(is_ecx_trader_liquidatable(
                    &short, i256(balance), 1, Price::new(mark).unwrap(), 0, 500, bounds(),
                ).unwrap(), is_incremental_trader_liquidatable_v2(
                    &marked_quote, mark, 0, 500, bounds(),
                ).unwrap());
            }
        }
        // A one-ECX long with one ECX collateral loses both P&L and collateral
        // value as price falls: at half the entry price its equity is zero.
        let mut long = flat_leaf(16);
        long.collateral_atoms = 0;
        long.cash_residual_numerator = 0;
        long.apply_trade_for_ecx_settlement(100_000_000, 30 * PRICE_SCALE, 0, bounds()).unwrap();
        assert!(is_ecx_trader_liquidatable(&long, i256(100_000_000), 1,
            Price::new(15 * PRICE_SCALE).unwrap(), 0, 500, bounds()).unwrap());
        assert!(!is_ecx_trader_liquidatable(&long, i256(100_000_000), 1,
            Price::new(30 * PRICE_SCALE).unwrap(), 0, 500, bounds()).unwrap());
    }

    #[test]
    fn ecx_equity_rejects_quote_cash_and_invalid_inputs() {
        use crate::ecx_collateral::ecx_trader_equity_numerator;
        let mut position = flat_leaf(16);
        position.collateral_atoms = 0;
        position.cash_residual_numerator = 0;
        let price = Price::new(1).unwrap();
        assert!(ecx_trader_equity_numerator(&position, i256(1), 0, price, 0, bounds()).is_err());
        assert!(ecx_trader_equity_numerator(&position,
            Int256V2::from_u128(bounds().maximum_abs_trader_collateral_atoms + 1),
            1, price, 0, bounds()).is_err());
        assert!(ecx_trader_equity_numerator(&position, i256(1), 1,
            Price::new(bounds().maximum_price_atoms + 1).unwrap(), 0, bounds()).is_err());
        position.collateral_atoms = 1;
        assert_eq!(ecx_trader_equity_numerator(&position, i256(1), 1, price, 0, bounds()),
            Err(ProtocolError::NonCanonicalEncoding));
        position.collateral_atoms = 0;
        position.cash_residual_numerator = -1;
        assert_eq!(ecx_trader_equity_numerator(&position, i256(1), 1, price, 0, bounds()),
            Err(ProtocolError::NonCanonicalEncoding));
    }

    #[test]
    fn ecx_position_engine_extracts_funding_and_pnl_without_quote_credit() {
        let mut ecx = flat_leaf(16);
        ecx.collateral_atoms = 0;
        ecx.cash_residual_numerator = 0;
        let mut quote = ecx.clone();
        // Open, grow, partially close, reverse, close: the two engines must
        // retain identical positions, while only quote mode accumulates cash.
        for (size, price, funding) in [(3,101,77),(2,102,81),(-2,103,91),(-5,99,105),(2,104,109)] {
            let before = quote.exact_cash_numerator(bounds()).unwrap();
            quote.apply_trade_exact(size, price, funding, bounds()).unwrap();
            let expected = quote.exact_cash_numerator(bounds()).unwrap().checked_sub(before).unwrap();
            let actual = ecx.apply_trade_for_ecx_settlement(size, price, funding, bounds()).unwrap();
            assert_eq!(actual, expected);
            assert_eq!(ecx.collateral_atoms, 0);
            assert_eq!(ecx.cash_residual_numerator, 0);
            let mut position_only = quote.clone();
            position_only.collateral_atoms = 0;
            position_only.cash_residual_numerator = 0;
            assert_eq!(ecx, position_only);
        }
        let before = ecx.clone();
        assert!(ecx.apply_trade_for_ecx_settlement(1, 0, 0, bounds()).is_err());
        assert_eq!(ecx, before);
        ecx.cash_residual_numerator = 1;
        let before = ecx.clone();
        assert_eq!(ecx.apply_trade_for_ecx_settlement(1, 1, 0, bounds()),
            Err(ProtocolError::NonCanonicalEncoding));
        assert_eq!(ecx, before);
    }

    #[test]
    fn close_and_reopen_resets_funding_checkpoint_without_lifetime_realized_state() {
        let mut trader = flat_leaf(16);
        trader.collateral_atoms = 1_000;
        trader.apply_trade_exact(3, 101, 77, bounds()).unwrap();
        assert_eq!(trader.last_funding_index_numerator, 77);
        let realized = trader.apply_trade_exact(-3, 103, 91, bounds()).unwrap();
        assert_eq!(realized, i256(6 * i128::from(FUNDING_INDEX_DENOMINATOR_V2)));
        // The ECX settlement adapter consumes the exact production numerator,
        // not the prematurely rounded integer USDD collateral delta. Here the
        // small close pays a fractional ECX atom, retained explicitly.
        let ecx = crate::ecx_collateral::quote_numerator_to_ecx(
            realized, Price::new(103).unwrap(),
        ).unwrap();
        assert_eq!(ecx.whole_ecx_atoms, Int256V2::ZERO);
        assert_eq!(ecx.remainder_numerator, realized);
        assert_eq!(ecx.denominator, 103 * u128::from(FUNDING_INDEX_DENOMINATOR_V2));
        assert_eq!(trader.position_size_atoms, 0);
        assert_eq!(trader.signed_cost_basis_numerator, Int256V2::ZERO);
        assert_eq!(trader.last_funding_index_numerator, 0);
        trader.apply_trade_exact(-2, 99, -41, bounds()).unwrap();
        assert_eq!(trader.position_size_atoms, -2);
        assert_eq!(trader.last_funding_index_numerator, -41);
        assert_eq!(
            trader.signed_cost_basis_numerator,
            i256(-198 * i128::from(FUNDING_INDEX_DENOMINATOR_V2))
        );
        // There is deliberately no lifetime realized-PnL field to grow
        // without bound; realized value exists only in exact cash.
        assert_eq!(trader.aggregate(bounds()).unwrap().leaf_count, 1);

        let mut insolvent_flat = flat_leaf(20);
        insolvent_flat.collateral_atoms = 0;
        insolvent_flat.cash_residual_numerator = -1;
        insolvent_flat.validate(bounds()).unwrap();
        assert_eq!(
            insolvent_flat
                .aggregate(bounds())
                .unwrap()
                .flat_negative_exact_cash_numerator,
            Uint256V2::from_u64(1)
        );

        let mut closes_into_negative = flat_leaf(21);
        closes_into_negative.collateral_atoms = 0;
        closes_into_negative.position_size_atoms = 1;
        closes_into_negative.signed_cost_basis_numerator =
            i256(2 * i128::from(FUNDING_INDEX_DENOMINATOR_V2));
        assert_eq!(
            closes_into_negative
                .apply_trade_exact(-1, 1, 0, bounds())
                .unwrap(),
            i256(-i128::from(FUNDING_INDEX_DENOMINATOR_V2))
        );
        assert_eq!(closes_into_negative.position_size_atoms, 0);
        assert_eq!(
            closes_into_negative
                .aggregate(bounds())
                .unwrap()
                .flat_negative_exact_cash_numerator,
            Uint256V2::from_u64(FUNDING_INDEX_DENOMINATOR_V2)
        );
    }

    #[test]
    fn aggregate_lazy_funding_term_matches_explicit_settlement() {
        let global = advance_exact_funding_index_v2(0, 300_000_001, 2_111).unwrap();
        let mut long = flat_leaf(17);
        long.collateral_atoms = 500;
        long.position_size_atoms = 4;
        long.signed_cost_basis_numerator =
            i256(4 * 300_000_000i128 * i128::from(FUNDING_INDEX_DENOMINATOR_V2));
        long.last_funding_index_numerator = 100;
        let mut short = flat_leaf(18);
        short.collateral_atoms = 500;
        short.position_size_atoms = -4;
        short.signed_cost_basis_numerator =
            i256(-4 * 300_000_000i128 * i128::from(FUNDING_INDEX_DENOMINATOR_V2));
        short.last_funding_index_numerator = -77;

        let aggregate = long
            .aggregate(bounds())
            .unwrap()
            .checked_add(short.aggregate(bounds()).unwrap())
            .unwrap();
        let lazy_root = SparseMerkleSumRootV2 {
            domain: SparseStateDomainV2::Trader,
            hash: [55; 32],
            aggregate,
        };
        let lazy_value =
            controlled_value_numerator_v2(lazy_root, 300_000_000, global, 0, bounds()).unwrap();

        long.settle_lazy_funding(global, bounds()).unwrap();
        short.settle_lazy_funding(global, bounds()).unwrap();
        let settled_aggregate = long
            .aggregate(bounds())
            .unwrap()
            .checked_add(short.aggregate(bounds()).unwrap())
            .unwrap();
        let settled_root = SparseMerkleSumRootV2 {
            domain: SparseStateDomainV2::Trader,
            hash: [56; 32],
            aggregate: settled_aggregate,
        };
        let settled_value =
            controlled_value_numerator_v2(settled_root, 300_000_000, global, 0, bounds()).unwrap();
        assert_eq!(lazy_value, settled_value);
    }

    #[test]
    fn exact_aggregate_removes_mark_dependent_rounding_defect() {
        let mut long = flat_leaf(10);
        long.collateral_atoms = 0;
        long.position_size_atoms = 1;
        long.signed_cost_basis_numerator =
            i256(100_000_001 * i128::from(FUNDING_INDEX_DENOMINATOR_V2));
        let mut short = flat_leaf(11);
        short.collateral_atoms = 0;
        short.position_size_atoms = -1;
        short.signed_cost_basis_numerator =
            i256(-100_000_000 * i128::from(FUNDING_INDEX_DENOMINATOR_V2));

        let aggregate = long
            .aggregate(bounds())
            .unwrap()
            .checked_add(short.aggregate(bounds()).unwrap())
            .unwrap();
        let root = SparseMerkleSumRootV2 {
            domain: SparseStateDomainV2::Trader,
            hash: [42; 32],
            aggregate,
        };
        let low = controlled_value_numerator_v2(root, 100_000_000, 0, 0, bounds()).unwrap();
        let high = controlled_value_numerator_v2(root, 200_000_000, 0, 0, bounds()).unwrap();
        assert_eq!(low, i256(-i128::from(FUNDING_INDEX_DENOMINATOR_V2)));
        assert_eq!(high, i256(-i128::from(FUNDING_INDEX_DENOMINATOR_V2)));
        assert_eq!(
            verify_controlled_value_v2(
                root,
                200_000_000,
                0,
                0,
                i256(-i128::from(FUNDING_INDEX_DENOMINATOR_V2)),
                bounds(),
            ),
            Err(ProtocolError::InvalidBondState)
        );
        assert_eq!(
            verify_controlled_value_v2(root, 200_000_000, 0, 0, Int256V2::ZERO, bounds()),
            Err(ProtocolError::ConservationViolation)
        );
    }

    #[test]
    fn controlled_value_rejects_unbalanced_or_out_of_bounds_roots() {
        let leaf = {
            let mut value = flat_leaf(12);
            value.position_size_atoms = 1;
            value.signed_cost_basis_numerator =
                i256(i128::from(PRICE_SCALE) * i128::from(FUNDING_INDEX_DENOMINATOR_V2));
            value
        };
        let root = SparseMerkleSumRootV2 {
            domain: SparseStateDomainV2::Trader,
            hash: [1; 32],
            aggregate: leaf.aggregate(bounds()).unwrap(),
        };
        assert_eq!(
            controlled_value_numerator_v2(root, PRICE_SCALE, 0, 0, bounds()),
            Err(ProtocolError::ConservationViolation)
        );
        let mut invalid = bounds();
        invalid.maximum_open_interest_atoms = u128::MAX;
        assert_eq!(invalid.validate(), Err(ProtocolError::InvalidBondState));

        // This profile and its complete expression fit U256, but the two
        // lifetime funding terms exceed the accepted symmetric signed-255
        // magnitude. It must fail at configuration validation rather than
        // strand a later reachable state.
        let mut signed_range_exceeded = bounds();
        signed_range_exceeded.maximum_open_interest_atoms = u128::MAX / 2;
        assert_eq!(
            signed_range_exceeded.validate(),
            Err(ProtocolError::ArithmeticOverflow)
        );
        let mut oi_not_i128_representable = bounds();
        oi_not_i128_representable.maximum_open_interest_atoms = i128::MAX as u128 + 1;
        assert_eq!(
            oi_not_i128_representable.validate(),
            Err(ProtocolError::InvalidBondState)
        );
        let mut controlled_not_i128_representable = bounds();
        controlled_not_i128_representable.maximum_total_controlled_atoms = i128::MAX as u128 + 1;
        assert_eq!(
            controlled_not_i128_representable.validate(),
            Err(ProtocolError::InvalidBondState)
        );
    }

    #[test]
    fn nullifier_empty_ladder_matches_independent_height_derivation() {
        for kind in [NullifierKindV2::Deposit, NullifierKindV2::Withdrawal] {
            let ladder = canonical_empty_nullifier_ladder_v2(kind).unwrap();
            assert_eq!(ladder.len(), SPARSE_MERKLE_SUM_DEPTH_V2 + 1);
            let mut slow = SparseNullifierNodeV2 {
                hash: empty_nullifier_leaf_hash_v2(kind),
                count: 0,
            };
            assert_eq!(ladder[0], slow);
            for (height, expected) in ladder.iter().enumerate().skip(1) {
                slow = SparseNullifierNodeV2 {
                    hash: nullifier_parent_hash_v2(
                        kind,
                        u16::try_from(height).unwrap(),
                        slow,
                        slow,
                        0,
                    ),
                    count: 0,
                };
                assert_eq!(*expected, slow);
            }
        }
    }

    #[test]
    fn nullifiers_are_empty_to_present_and_replay_fails() {
        let kind = NullifierKindV2::Deposit;
        let initial = canonical_empty_nullifier_root_v2(kind);
        let update = SparseNullifierUpdateV2 {
            kind,
            nullifier: [21; 32],
            path: canonical_empty_nullifier_path_v2(kind),
        };
        let next =
            verify_sparse_nullifier_updates_v2(initial, std::slice::from_ref(&update), 1).unwrap();
        assert_eq!(next.count, 1);
        assert_eq!(
            verify_sparse_nullifier_updates_v2(next, std::slice::from_ref(&update), 1),
            Err(ProtocolError::InvalidMerkleProof)
        );
        let mut substituted = update;
        substituted.kind = NullifierKindV2::Withdrawal;
        assert_eq!(
            verify_sparse_nullifier_updates_v2(initial, &[substituted], 1),
            Err(ProtocolError::InvalidMerkleProof)
        );

        // Empty batches still validate the canonical root shape.  In
        // particular, a hash from the generic trader aggregate tree cannot be
        // reinterpreted as a count-only nullifier root.
        let contaminated = SparseNullifierRootV2 {
            kind,
            hash: canonical_empty_sparse_root_v2(kind.domain()).hash,
            count: 0,
        };
        assert_eq!(
            verify_sparse_nullifier_updates_v2(contaminated, &[], 1),
            Err(ProtocolError::NonCanonicalEncoding)
        );
    }

    #[test]
    fn compact_nullifier_paths_have_a_bounded_exact_maximum_encoding() {
        let mut updates = Vec::with_capacity(MAX_SPARSE_MERKLE_SUM_UPDATES_PER_BATCH_V2);
        for index in 0..MAX_SPARSE_MERKLE_SUM_UPDATES_PER_BATCH_V2 {
            let nullifier = tagged_hash("ECX/test/nullifier-max-batch", &index.to_be_bytes());
            updates.push(SparseNullifierUpdateV2 {
                kind: NullifierKindV2::Withdrawal,
                nullifier,
                path: canonical_empty_nullifier_path_v2(NullifierKindV2::Withdrawal),
            });
        }
        let encoded = canonical_nullifier_update_batch_bytes_v2(&updates).unwrap();
        assert_eq!(encoded.len(), 788_738);
        assert!(encoded.len() < MAX_SPARSE_NULLIFIER_UPDATE_BATCH_BYTES_V2);
        updates.push(updates.last().unwrap().clone());
        assert_eq!(
            canonical_nullifier_update_batch_bytes_v2(&updates),
            Err(ProtocolError::InvalidMerkleProof)
        );
    }

    #[test]
    fn raw_trader_paths_are_capped_and_shared_frontier_handles_full_batch() {
        let path = canonical_empty_sparse_path_v2(SparseStateDomainV2::Trader);
        let mut previous = flat_leaf(13);
        let initial = one_leaf_root(&previous);
        let raw_path_capacity = 32;
        let mut updates = Vec::with_capacity(raw_path_capacity);
        for index in 0..raw_path_capacity {
            let mut next = previous.clone();
            next.account_nonce = u128::try_from(index + 1).unwrap();
            next.order_generation = u128::try_from(index + 1).unwrap();
            next.salt = tagged_hash("ECX/test/incremental-max-batch", &index.to_be_bytes());
            updates.push(TraderStateUpdateV2 {
                trader: previous.trader,
                old_leaf: Some(previous),
                new_leaf: Some(next.clone()),
                path: path.clone(),
                continues_previous_key: index != 0,
            });
            previous = next;
        }
        let encoded = canonical_trader_update_batch_bytes_v2(&updates).unwrap();
        assert_eq!(encoded.len(), 2_986_562);
        assert!(encoded.len() < MAX_CHAINED_SPARSE_MERKLE_SUM_UPDATE_BATCH_BYTES_V2);
        let root = verify_chained_trader_updates_v2(initial, &updates, bounds(), raw_path_capacity)
            .unwrap();
        assert_eq!(root.aggregate, previous.aggregate(bounds()).unwrap());

        // The fixed-size aggregate makes a 64-entry raw-path encoding exceed
        // the isolated 3 MiB class cap.  This fail-closed reference API is not
        // the successor witness: the shared-prefix frontier above carries all
        // 64 unique keys in 64,645 bytes when every frontier subtree is empty.
        let mut oversized = updates;
        for index in raw_path_capacity..MAX_SPARSE_MERKLE_SUM_UPDATES_PER_BATCH_V2 {
            let mut next = previous.clone();
            next.account_nonce = u128::try_from(index + 1).unwrap();
            next.order_generation = u128::try_from(index + 1).unwrap();
            next.salt = tagged_hash("ECX/test/incremental-max-batch", &index.to_be_bytes());
            oversized.push(TraderStateUpdateV2 {
                trader: previous.trader,
                old_leaf: Some(previous),
                new_leaf: Some(next.clone()),
                path: path.clone(),
                continues_previous_key: true,
            });
            previous = next;
        }
        assert_eq!(
            canonical_trader_update_batch_bytes_v2(&oversized),
            Err(ProtocolError::InvalidMerkleProof)
        );
    }

    #[test]
    fn aggregate_and_path_arithmetic_overflow_fail_closed() {
        let left = TraderAggregateV2 {
            leaf_count: 1,
            total_collateral_atoms: i128::MAX,
            ..TraderAggregateV2::ZERO
        };
        let right = TraderAggregateV2 {
            leaf_count: 1,
            total_collateral_atoms: 1,
            ..TraderAggregateV2::ZERO
        };
        assert_eq!(
            left.checked_add(right),
            Err(ProtocolError::ArithmeticOverflow)
        );

        let mut update = SparseMerkleSumUpdateV2 {
            domain: SparseStateDomainV2::Trader,
            key: [0; 32],
            old_leaf: SparseMerkleSumLeafV2::EMPTY,
            new_leaf: SparseMerkleSumLeafV2::EMPTY,
            path: canonical_empty_sparse_path_v2(SparseStateDomainV2::Trader),
            continues_previous_key: false,
        };
        update.path.siblings[0].aggregate.leaf_count = 2;
        assert_eq!(
            update.verify(canonical_empty_sparse_root_v2(SparseStateDomainV2::Trader)),
            Err(ProtocolError::InvalidMerkleProof)
        );
    }

    #[test]
    fn successor_counts_cover_maximum_per_block_across_u64_height_namespace() {
        let lifetime_operations = u128::from(u64::MAX)
            .checked_add(1)
            .unwrap()
            .checked_mul(MAX_SPARSE_MERKLE_SUM_UPDATES_PER_BATCH_V2 as u128)
            .unwrap();
        assert!(lifetime_operations > u128::from(u64::MAX));
        assert!(lifetime_operations < u128::MAX);
        let aggregate = TraderAggregateV2 {
            leaf_count: lifetime_operations,
            ..TraderAggregateV2::ZERO
        };
        assert_eq!(aggregate.leaf_count, 1u128 << 70);
        assert_eq!(
            aggregate.leaf_count,
            MAX_REACHABLE_INCREMENTAL_LEAF_COUNT_V2
        );
        let nullifiers = SparseNullifierRootV2 {
            kind: NullifierKindV2::Deposit,
            hash: [1; 32],
            count: lifetime_operations,
        };
        nullifiers.validate().unwrap();

        let mut trader = flat_leaf(19);
        trader.account_nonce = lifetime_operations;
        trader.order_generation = lifetime_operations;
        trader.validate(bounds()).unwrap();

        let too_many = TraderAggregateV2 {
            leaf_count: MAX_REACHABLE_INCREMENTAL_LEAF_COUNT_V2 + 1,
            ..TraderAggregateV2::ZERO
        };
        assert_eq!(
            too_many.validate(bounds()),
            Err(ProtocolError::InvalidBondState)
        );
        let too_many_nullifiers = SparseNullifierRootV2 {
            kind: NullifierKindV2::Deposit,
            hash: [1; 32],
            count: MAX_REACHABLE_INCREMENTAL_LEAF_COUNT_V2 + 1,
        };
        assert_eq!(
            too_many_nullifiers.validate(),
            Err(ProtocolError::InvalidMerkleProof)
        );
    }

    #[test]
    fn order_priority_aggregate_matches_bid_ask_price_time_fifo() {
        let (buy_low, _) = order_leaf(21, Side::Buy, 100, 5, 1, 0);
        let (buy_high_late, _) = order_leaf(22, Side::Buy, 110, 5, 9, 0);
        let (buy_high_early, _) = order_leaf(23, Side::Buy, 110, 5, 2, 0);
        let (sell_high, _) = order_leaf(24, Side::Sell, 120, 5, 1, 0);
        let (sell_low, _) = order_leaf(25, Side::Sell, 90, 5, 9, 0);
        let context = order_context();
        let aggregate = buy_low
            .aggregate(context)
            .unwrap()
            .checked_add(buy_high_late.aggregate(context).unwrap())
            .unwrap()
            .checked_add(buy_high_early.aggregate(context).unwrap())
            .unwrap()
            .checked_add(sell_high.aggregate(context).unwrap())
            .unwrap()
            .checked_add(sell_low.aggregate(context).unwrap())
            .unwrap();
        assert_eq!(aggregate.best_buy, Some(buy_high_early.priority()));
        assert_eq!(aggregate.best_sell, Some(sell_low.priority()));
        assert_eq!(aggregate.leaf_count, 5);
        assert_eq!(
            aggregate
                .total_remaining_quantity_atoms
                .try_to_u128()
                .unwrap(),
            25
        );
    }

    #[test]
    fn typed_order_mutations_bind_trader_risk_and_preserve_fifo_terms() {
        let context = order_context();
        let (old, trader) = order_leaf(26, Side::Sell, 100, 10, 7, 3);
        let mut next = old.clone();
        next.remaining_quantity_atoms = 6;
        next.salt = [99; 32];
        let partial = OrderIndexOperationV2 {
            kind: OrderIndexOperationKindV2::PartialFill,
            order_id: old.order_id(),
            old_leaf: Some(old.clone()),
            new_leaf: Some(next.clone()),
            trader_leaf: trader.clone(),
            filled_quantity_atoms: 4,
        };
        partial.validate(context, bounds()).unwrap();

        let mut bad_price = next.clone();
        bad_price.signed_order.order.limit_price = Price::new(101).unwrap();
        let mut forged = partial.clone();
        forged.new_leaf = Some(bad_price);
        assert!(forged.validate(context, bounds()).is_err());
        let mut bad_sequence = partial.clone();
        bad_sequence.new_leaf.as_mut().unwrap().received_sequence += 1;
        assert_eq!(
            bad_sequence.validate(context, bounds()),
            Err(ProtocolError::InvalidMerkleProof)
        );
        let mut overfill = partial.clone();
        overfill.filled_quantity_atoms = 11;
        assert_eq!(
            overfill.validate(context, bounds()),
            Err(ProtocolError::InvalidMerkleProof)
        );

        let mut expired_context = context;
        expired_context.sidechain_height = 201;
        assert_eq!(
            partial.validate(expired_context, bounds()),
            Err(ProtocolError::InvalidMerkleProof)
        );
        let mut stale = partial;
        stale.trader_leaf.order_generation = 4;
        assert_eq!(
            stale.validate(context, bounds()),
            Err(ProtocolError::InvalidMerkleProof)
        );
    }

    #[test]
    fn compact_order_frontier_is_iterative_complete_and_bounded() {
        let context = order_context();
        let mut operations = Vec::new();
        for seed in 70u8..=133u8 {
            let side = if seed % 2 == 0 { Side::Buy } else { Side::Sell };
            let (leaf, trader) = order_leaf(
                seed,
                side,
                1_000 + u64::from(seed),
                100,
                u128::from(seed),
                0,
            );
            operations.push(OrderIndexOperationV2 {
                kind: OrderIndexOperationKindV2::Insert,
                order_id: leaf.order_id(),
                old_leaf: None,
                new_leaf: Some(leaf),
                trader_leaf: trader,
                filled_quantity_atoms: 0,
            });
        }
        let proof = OrderIndexBatchProofV2::for_canonical_empty_root(operations, context, bounds())
            .unwrap();
        let bytes = proof.canonical_bytes_checked(context, bounds()).unwrap();
        assert!(proof.frontier.len() <= MAX_ORDER_INDEX_SHARED_FRONTIER_ITEMS_V2);
        assert!(bytes.len() < MAX_ORDER_INDEX_UPDATE_BATCH_BYTES_V2);
        let mut unit = proof.operations[0]
            .new_leaf
            .as_ref()
            .unwrap()
            .aggregate(context)
            .unwrap();
        let (opposite_leaf, _) = order_leaf(134, Side::Sell, 500, 2, 500, 0);
        if unit.best_sell.is_none() {
            unit = unit
                .checked_add(opposite_leaf.aggregate(context).unwrap())
                .unwrap();
        }
        let mut all_occupied = proof.clone();
        for (index, item) in all_occupied.frontier.iter_mut().enumerate() {
            *item = OrderIndexFrontierItemV2::Occupied(OrderIndexNodeV2 {
                hash: tagged_hash("ECX/test/order-frontier-occupied", &index.to_be_bytes()),
                aggregate: unit,
            });
        }
        let occupied_bytes = all_occupied
            .canonical_bytes_checked(context, bounds())
            .unwrap();
        assert_eq!(occupied_bytes.len(), 3_969_209);
        assert!(occupied_bytes.len() < MAX_ORDER_INDEX_UPDATE_BATCH_BYTES_V2);
        let (mut maximum_old, maximum_trader) =
            order_leaf(135, Side::Buy, u64::MAX, 2, u128::MAX, 0);
        let mut maximum_new = maximum_old.clone();
        maximum_new.remaining_quantity_atoms = 1;
        maximum_new.salt = [136; 32];
        maximum_old.remaining_quantity_atoms = 2;
        let maximum_operation = OrderIndexOperationV2 {
            kind: OrderIndexOperationKindV2::PartialFill,
            order_id: maximum_old.order_id(),
            old_leaf: Some(maximum_old),
            new_leaf: Some(maximum_new),
            trader_leaf: maximum_trader,
            filled_quantity_atoms: 1,
        };
        let maximum_frontier_item = OrderIndexFrontierItemV2::Occupied(OrderIndexNodeV2 {
            hash: [137; 32],
            aggregate: unit,
        });
        let universal_wire_ceiling = 1usize
            + 2
            + MAX_ORDER_INDEX_OPERATIONS_PER_BATCH_V2 * maximum_operation.canonical_bytes().len()
            + 2
            + MAX_ORDER_INDEX_SHARED_FRONTIER_ITEMS_V2
                * maximum_frontier_item.canonical_bytes().len();
        assert_eq!(universal_wire_ceiling, 4_012_613);
        assert!(universal_wire_ceiling < MAX_ORDER_INDEX_UPDATE_BATCH_BYTES_V2);
        let next = proof
            .verify(canonical_empty_order_index_root_v2(), context, bounds())
            .unwrap();
        assert_eq!(next.aggregate.leaf_count, 64);
        let mut extra = proof.clone();
        extra
            .frontier
            .push(OrderIndexFrontierItemV2::CanonicalEmpty);
        assert_eq!(
            extra.verify(canonical_empty_order_index_root_v2(), context, bounds()),
            Err(ProtocolError::InvalidMerkleProof)
        );
        let mut substituted = proof;
        substituted.operations[0].order_id = [42; 32];
        assert_eq!(
            substituted.verify(canonical_empty_order_index_root_v2(), context, bounds()),
            Err(ProtocolError::InvalidMerkleProof)
        );
        assert_eq!(
            u8::from(INCREMENTAL_SUCCESSOR_GLOBAL_WITNESS_BOUND_PROVEN_V2),
            0
        );
    }

    #[test]
    fn position_risk_extrema_and_margin_replay_are_typed_and_conservative() {
        let mut long = flat_leaf(61);
        long.position_size_atoms = 10;
        long.signed_cost_basis_numerator =
            Int256V2::from_u128(10 * 100 * u128::from(FUNDING_INDEX_DENOMINATOR_V2));
        long.last_funding_index_numerator = 7;
        let long_extrema = PositionRiskExtremaV2::from_trader(&long, 600, bounds())
            .unwrap()
            .unwrap();
        assert_eq!(long_extrema.side, DeficitSideV2::Long);

        let mut short = flat_leaf(62);
        short.position_size_atoms = -8;
        short.signed_cost_basis_numerator =
            Int256V2::from_i128(-8 * 100 * i128::from(FUNDING_INDEX_DENOMINATOR_V2));
        short.last_funding_index_numerator = 7;
        short.selected_initial_margin_bps = 5_000;
        let short_extrema = PositionRiskExtremaV2::from_trader(&short, 600, bounds())
            .unwrap()
            .unwrap();
        let aggregate = RiskExtremaAggregateV2::from_leaf(long_extrema)
            .unwrap()
            .checked_add(RiskExtremaAggregateV2::from_leaf(short_extrema).unwrap())
            .unwrap();
        assert_eq!(aggregate.leaf_count, 2);
        assert!(!aggregate
            .all_positions_operationally_safe(
                long_extrema.cut_x_numerator.checked_sub(i256(1)).unwrap(),
                short_extrema.cut_x_numerator.checked_add(i256(1)).unwrap(),
            )
            .unwrap());
        assert!(aggregate
            .all_positions_operationally_safe(
                long_extrema.cut_x_numerator,
                short_extrema.cut_x_numerator,
            )
            .unwrap());

        let old = flat_leaf(63);
        let mut next = old.clone();
        next.position_size_atoms = 1;
        next.signed_cost_basis_numerator =
            Int256V2::from_u128(100 * u128::from(FUNDING_INDEX_DENOMINATOR_V2));
        replay_selected_position_margin_v2(&old, &mut next, 5_000, 1_000, bounds()).unwrap();
        assert_eq!(next.selected_initial_margin_bps, 5_000);
        let prior = next.clone();
        next.position_size_atoms = 0;
        next.signed_cost_basis_numerator = Int256V2::ZERO;
        next.last_funding_index_numerator = 0;
        replay_selected_position_margin_v2(&prior, &mut next, 1_000, 1_000, bounds()).unwrap();
        assert_eq!(next.selected_initial_margin_bps, 1_000);
    }

    #[test]
    fn chained_order_transcript_authenticates_immediate_fifo_root_and_has_exact_bound() {
        let context = order_context();
        let (old, trader) = order_leaf(64, Side::Sell, 100, 10, 1, 0);
        let insert = OrderIndexOperationV2 {
            kind: OrderIndexOperationKindV2::Insert,
            order_id: old.order_id(),
            old_leaf: None,
            new_leaf: Some(old.clone()),
            trader_leaf: trader.clone(),
            filled_quantity_atoms: 0,
        };
        let mut partial_leaf = old.clone();
        partial_leaf.remaining_quantity_atoms = 4;
        partial_leaf.salt = [101; 32];
        let partial = OrderIndexOperationV2 {
            kind: OrderIndexOperationKindV2::PartialFill,
            order_id: old.order_id(),
            old_leaf: Some(old.clone()),
            new_leaf: Some(partial_leaf),
            trader_leaf: trader,
            filled_quantity_atoms: 6,
        };
        let empty_path = vec![OrderIndexFrontierItemV2::CanonicalEmpty; SPARSE_MERKLE_SUM_DEPTH_V2];
        let transcript = ChainedOrderIndexTranscriptV2 {
            actions: vec![
                ChainedOrderIndexActionV2 {
                    operation: insert,
                    siblings_leaf_to_root: empty_path.clone(),
                },
                ChainedOrderIndexActionV2 {
                    operation: partial,
                    siblings_leaf_to_root: empty_path,
                },
            ],
        };
        let (root, predecessors) = transcript
            .verify_with_predecessor_roots(canonical_empty_order_index_root_v2(), context, bounds())
            .unwrap();
        assert_eq!(predecessors.len(), 2);
        assert_eq!(predecessors[0], canonical_empty_order_index_root_v2());
        assert_eq!(predecessors[1].aggregate.best_sell, Some(old.priority()));
        assert_eq!(root.aggregate.leaf_count, 1);
        assert_eq!(
            root.aggregate
                .total_remaining_quantity_atoms
                .try_to_u128()
                .unwrap(),
            4
        );
        verify_best_crossing_maker_v2(
            root,
            transcript.actions[1].operation.new_leaf.as_ref().unwrap(),
            Side::Buy,
            100,
            2,
        )
        .unwrap();

        let mut skipped = transcript.clone();
        skipped.actions[1]
            .operation
            .old_leaf
            .as_mut()
            .unwrap()
            .received_sequence = 9;
        assert!(skipped
            .verify(canonical_empty_order_index_root_v2(), context, bounds())
            .is_err());

        let (wire_leaf, wire_trader) = order_leaf(65, Side::Buy, 100, 2, 1, 0);
        let unit = wire_leaf.aggregate(context).unwrap();
        let occupied = OrderIndexFrontierItemV2::Occupied(OrderIndexNodeV2 {
            hash: [77; 32],
            aggregate: unit,
        });
        let mut wire_next = wire_leaf.clone();
        wire_next.remaining_quantity_atoms = 1;
        wire_next.salt = [102; 32];
        let mut wire_old = wire_leaf;
        wire_old.remaining_quantity_atoms = 2;
        let wire_action = ChainedOrderIndexActionV2 {
            operation: OrderIndexOperationV2 {
                kind: OrderIndexOperationKindV2::PartialFill,
                order_id: wire_old.order_id(),
                old_leaf: Some(wire_old),
                new_leaf: Some(wire_next),
                trader_leaf: wire_trader,
                filled_quantity_atoms: 1,
            },
            siblings_leaf_to_root: vec![occupied; SPARSE_MERKLE_SUM_DEPTH_V2],
        };
        let maximum = ChainedOrderIndexTranscriptV2 {
            actions: vec![wire_action; MAX_ORDER_INDEX_OPERATIONS_PER_BATCH_V2],
        };
        let bytes = maximum.canonical_bytes_checked(context, bounds()).unwrap();
        assert_eq!(bytes.len(), 3_173_314);
        assert!(bytes.len() < MAX_CHAINED_ORDER_INDEX_TRANSCRIPT_BYTES_V2);
    }

    #[test]
    fn liquidation_uses_exact_one_sided_head_without_an_eligible_range_gap() {
        let context = order_context();
        let (best_bid, _) = order_leaf(105, Side::Buy, 100, 10, 1, 0);
        let bid_root = OrderIndexRootV2 {
            hash: [0x51; 32],
            aggregate: best_bid.aggregate(context).unwrap(),
        };
        assert_eq!(
            verify_best_liquidation_maker_v2(bid_root, &best_bid, context, 10, 90, 110),
            Ok(90)
        );

        // If the authenticated highest bid is below the lower bound, every
        // deeper bid is lower as well. The head is rejected and no hidden
        // eligible maker can exist behind it.
        let (low_head, _) = order_leaf(106, Side::Buy, 89, 10, 1, 0);
        let low_root = OrderIndexRootV2 {
            hash: [0x52; 32],
            aggregate: low_head.aggregate(context).unwrap(),
        };
        assert_eq!(
            verify_best_liquidation_maker_v2(low_root, &low_head, context, 10, 90, 110),
            Err(ProtocolError::PriceTimePriorityViolation)
        );

        // A lower-priority bid cannot be substituted while a better bid is
        // committed by the immediate predecessor root.
        assert_eq!(
            verify_best_liquidation_maker_v2(bid_root, &low_head, context, 10, 90, 110),
            Err(ProtocolError::PriceTimePriorityViolation)
        );

        let (best_ask, _) = order_leaf(107, Side::Sell, 100, 10, 1, 0);
        let ask_root = OrderIndexRootV2 {
            hash: [0x53; 32],
            aggregate: best_ask.aggregate(context).unwrap(),
        };
        assert_eq!(
            verify_best_liquidation_maker_v2(ask_root, &best_ask, context, -10, 90, 110),
            Ok(110)
        );
        let (high_head, _) = order_leaf(108, Side::Sell, 111, 10, 1, 0);
        let high_root = OrderIndexRootV2 {
            hash: [0x54; 32],
            aggregate: high_head.aggregate(context).unwrap(),
        };
        assert_eq!(
            verify_best_liquidation_maker_v2(high_root, &high_head, context, -10, 90, 110,),
            Err(ProtocolError::PriceTimePriorityViolation)
        );
    }

    #[test]
    fn trader_economic_mutation_chain_is_exact_ordered_and_tamper_evident() {
        let old = flat_leaf(61);
        let first = IncrementalTraderEconomicMutationV2 {
            kind: IncrementalTraderMutationKindV2::Deposit,
            action_id: [71; 32],
            exact_cash_delta_numerator: Int256V2::from_u128(
                5 * u128::from(EXACT_ACCOUNTING_DENOMINATOR_V2),
            ),
            position_size_delta_atoms: 0,
            signed_cost_basis_delta_numerator: Int256V2::ZERO,
            funding_checkpoint_after: None,
            account_nonce_increment: 1,
            order_generation_increment: 0,
            selected_initial_margin_bps_after: None,
        };
        let second = IncrementalTraderEconomicMutationV2 {
            kind: IncrementalTraderMutationKindV2::BondActionRejection,
            action_id: [72; 32],
            exact_cash_delta_numerator: Int256V2::ZERO,
            position_size_delta_atoms: 0,
            signed_cost_basis_delta_numerator: Int256V2::ZERO,
            funding_checkpoint_after: None,
            account_nonce_increment: 1,
            order_generation_increment: 1,
            selected_initial_margin_bps_after: Some(2_000),
        };
        let mut expected = old.clone();
        expected
            .apply_exact_cash_delta_numerator(first.exact_cash_delta_numerator, bounds())
            .unwrap();
        expected.account_nonce += 2;
        expected.order_generation += 1;
        expected.selected_initial_margin_bps = 2_000;
        expected.salt = [73; 32];
        let chain = IncrementalTraderMutationChainV2 {
            trader: old.trader,
            old_leaf: old,
            mutations: vec![first, second],
            final_salt: expected.salt,
            expected_new_leaf: expected,
        };
        let root = verify_incremental_trader_mutation_chain_v2(&chain, bounds(), 64).unwrap();
        assert_ne!(root, [0; 32]);

        let mut reordered = chain.clone();
        reordered.mutations.swap(0, 1);
        assert_ne!(
            verify_incremental_trader_mutation_chain_v2(&reordered, bounds(), 64).unwrap(),
            root
        );
        let mut duplicate = chain.clone();
        duplicate.mutations[1].action_id = duplicate.mutations[0].action_id;
        assert_eq!(
            verify_incremental_trader_mutation_chain_v2(&duplicate, bounds(), 64),
            Err(ProtocolError::InvalidMerkleProof)
        );
        let mut forged = chain;
        forged.expected_new_leaf.collateral_atoms += 1;
        assert_eq!(
            verify_incremental_trader_mutation_chain_v2(&forged, bounds(), 64),
            Err(ProtocolError::InvalidMerkleProof)
        );
    }

    #[test]
    fn risk_extrema_conservatively_dominates_finite_nested_margin_rounding() {
        let params = RiskParams::default();
        let mut saw_conservative_rejection = false;
        for size in [-9i64, -3, -1, 1, 3, 9] {
            for entry in [1u64, 3, 10, 31] {
                for price in 1u64..=40 {
                    for collateral in -2i128..=12 {
                        let mut trader = flat_leaf(66);
                        trader.collateral_atoms = collateral;
                        trader.position_size_atoms = size;
                        trader.signed_cost_basis_numerator =
                            Int256V2::checked_product_i64_i128(size, i128::from(entry))
                                .unwrap()
                                .checked_mul_u64(FUNDING_INDEX_DENOMINATOR_V2)
                                .unwrap();
                        let extrema = PositionRiskExtremaV2::from_trader(
                            &trader,
                            params.maintenance_margin_bps,
                            bounds(),
                        )
                        .unwrap()
                        .unwrap();
                        let aggregate = RiskExtremaAggregateV2::from_leaf(extrema).unwrap();
                        let (long_x, short_x) = operational_risk_coordinates_v2(
                            price,
                            price,
                            0,
                            params.maintenance_margin_bps,
                            bounds(),
                        )
                        .unwrap();
                        let incremental_safe = aggregate
                            .all_positions_operationally_safe(long_x, short_x)
                            .unwrap();
                        let position = Position {
                            size,
                            entry_price: entry,
                            last_funding_index: 0,
                        };
                        let mark = Price::new(price).unwrap();
                        let finite_safe = equity(Amount(collateral), &position, mark).unwrap()
                            >= required_margin(&position, mark, MarginKind::Maintenance, params)
                                .unwrap();
                        assert!(!incremental_safe || finite_safe);
                        saw_conservative_rejection |= finite_safe && !incremental_safe;
                    }
                }
            }
        }
        assert!(saw_conservative_rejection);
    }
}
