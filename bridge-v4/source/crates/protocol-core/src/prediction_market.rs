//! Integer-only binary prediction-market transitions suitable for proof and
//! Simplicity covenant implementations.
//!
//! The pool is a fully-collateralized fixed-product market maker. One unit of
//! collateral mints one YES and one NO outcome unit. A buy adds complete sets
//! and removes the requested outcome; a sell adds the outcome and redeems the
//! greatest whole number of complete sets that preserves the invariant. No
//! floating-point, clock, I/O, or implementation-defined encoding is used.

use crate::codec::{put_i128, put_u128, put_u32, put_u64, put_u8, CanonicalEncode};
use crate::hash::{canonical_hash, Hash32};
use crate::merkle::ordered_root;
use crate::order::Signature64;
use crate::ProtocolError;
#[cfg(feature = "prediction-market-guest")]
use k256::schnorr::{Signature as K256Signature, VerifyingKey};
#[cfg(not(feature = "prediction-market-guest"))]
use secp256k1::schnorr;
#[cfg(any(not(feature = "prediction-market-guest"), test))]
use secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};

pub const PREDICTION_MARKET_VERSION_V1: u8 = 1;
pub const PROBABILITY_SCALE_PPB: u64 = 1_000_000_000;
pub const PREDICTION_MARKET_PUBLIC_VALUES_VERSION_V1: u32 = 1;
pub const PREDICTION_MARKET_PUBLIC_VALUES_BYTES_V1: usize = 336;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BinaryOutcomeV1 {
    No = 0,
    Yes = 1,
}

impl CanonicalEncode for BinaryOutcomeV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, *self as u8);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PredictionMarketSideV1 {
    Buy = 0,
    Sell = 1,
}

impl CanonicalEncode for PredictionMarketSideV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, *self as u8);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PredictionMarketConfigV1 {
    pub market_id: Hash32,
    pub collateral_asset: Hash32,
    pub yes_asset: Hash32,
    pub no_asset: Hash32,
    pub pair_id: [u8; 16],
    pub strike_price_ticks: u64,
    pub expiry_parent_mtp: u64,
}

impl PredictionMarketConfigV1 {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.market_id == [0; 32]
            || self.collateral_asset == [0; 32]
            || self.yes_asset == [0; 32]
            || self.no_asset == [0; 32]
            || self.yes_asset == self.no_asset
            || self.collateral_asset == self.yes_asset
            || self.collateral_asset == self.no_asset
            || self.pair_id == [0; 16]
            || self.strike_price_ticks == 0
            || self.expiry_parent_mtp == 0
        {
            return Err(ProtocolError::InvalidMarket);
        }
        Ok(())
    }

    pub fn commitment(&self) -> Result<Hash32, ProtocolError> {
        self.validate()?;
        Ok(canonical_hash("ECX/prediction-market-config/v1", self))
    }
}

impl CanonicalEncode for PredictionMarketConfigV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.market_id);
        out.extend_from_slice(&self.collateral_asset);
        out.extend_from_slice(&self.yes_asset);
        out.extend_from_slice(&self.no_asset);
        out.extend_from_slice(&self.pair_id);
        put_u64(out, self.strike_price_ticks);
        put_u64(out, self.expiry_parent_mtp);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PredictionMarketStateV1 {
    pub version: u8,
    pub configuration_hash: Hash32,
    pub account_state_root: Hash32,
    pub yes_reserve_units: u64,
    pub no_reserve_units: u64,
    pub collateral_locked_units: u64,
    pub cumulative_volume_units: u128,
    pub sequence: u64,
    pub last_parent_mtp: u64,
}

impl PredictionMarketStateV1 {
    pub fn validate(&self, config: &PredictionMarketConfigV1) -> Result<(), ProtocolError> {
        config.validate()?;
        if self.version != PREDICTION_MARKET_VERSION_V1
            || self.configuration_hash != config.commitment()?
            || self.account_state_root == [0; 32]
            || self.yes_reserve_units == 0
            || self.no_reserve_units == 0
            || self.collateral_locked_units == 0
            || self.last_parent_mtp >= config.expiry_parent_mtp
        {
            return Err(ProtocolError::InvalidMarket);
        }
        Ok(())
    }

    pub fn commitment(&self, config: &PredictionMarketConfigV1) -> Result<Hash32, ProtocolError> {
        self.validate(config)?;
        Ok(canonical_hash("ECX/prediction-market-state/v1", self))
    }

    pub fn yes_probability_ppb(&self) -> Result<u32, ProtocolError> {
        let total = self
            .yes_reserve_units
            .checked_add(self.no_reserve_units)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        let value = (u128::from(self.no_reserve_units) * u128::from(PROBABILITY_SCALE_PPB))
            / u128::from(total);
        u32::try_from(value).map_err(|_| ProtocolError::ArithmeticOverflow)
    }
}

impl CanonicalEncode for PredictionMarketStateV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.configuration_hash);
        out.extend_from_slice(&self.account_state_root);
        put_u64(out, self.yes_reserve_units);
        put_u64(out, self.no_reserve_units);
        put_u64(out, self.collateral_locked_units);
        put_u128(out, self.cumulative_volume_units);
        put_u64(out, self.sequence);
        put_u64(out, self.last_parent_mtp);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PredictionMarketAccountV1 {
    pub trader_commitment: Hash32,
    pub available_collateral_units: u64,
    pub yes_shares_units: u64,
    pub no_shares_units: u64,
    pub nonce: u64,
}

impl PredictionMarketAccountV1 {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.trader_commitment == [0; 32] {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        Ok(())
    }

    pub fn commitment(&self) -> Result<Hash32, ProtocolError> {
        self.validate()?;
        Ok(canonical_hash("ECX/prediction-market-account/v1", self))
    }
}

impl CanonicalEncode for PredictionMarketAccountV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.trader_commitment);
        put_u64(out, self.available_collateral_units);
        put_u64(out, self.yes_shares_units);
        put_u64(out, self.no_shares_units);
        put_u64(out, self.nonce);
    }
}

pub fn prediction_market_account_root_v1(
    accounts: &[PredictionMarketAccountV1],
) -> Result<Hash32, ProtocolError> {
    if accounts.is_empty() || accounts.len() > 1024 {
        return Err(ProtocolError::InvalidMarket);
    }
    let mut sorted = accounts.to_vec();
    sorted.sort_by_key(|account| account.trader_commitment);
    if sorted
        .windows(2)
        .any(|pair| pair[0].trader_commitment == pair[1].trader_commitment)
    {
        return Err(ProtocolError::DuplicateMerkleKey);
    }
    let commitments = sorted
        .iter()
        .map(PredictionMarketAccountV1::commitment)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ordered_root(
        "ECX/prediction-market-accounts/v1",
        &commitments,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PredictionMarketOrderV1 {
    pub version: u8,
    pub chain_id: Hash32,
    pub market_id: Hash32,
    pub trader_commitment: Hash32,
    /// SHA256 of the exact Elements scriptPubKey that receives sell proceeds.
    pub payout_script_sha256: Hash32,
    pub nonce: u64,
    pub outcome: BinaryOutcomeV1,
    pub side: PredictionMarketSideV1,
    /// Exact outcome units bought or sold.
    pub outcome_quantity_units: u64,
    /// Maximum post-trade outcome probability for buys; minimum for sells.
    pub limit_probability_ppb: u32,
}

impl PredictionMarketOrderV1 {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != PREDICTION_MARKET_VERSION_V1 {
            return Err(ProtocolError::UnsupportedVersion);
        }
        if self.chain_id == [0; 32]
            || self.market_id == [0; 32]
            || self.trader_commitment == [0; 32]
            || self.payout_script_sha256 == [0; 32]
            || self.outcome_quantity_units == 0
            || self.limit_probability_ppb == 0
            || u64::from(self.limit_probability_ppb) >= PROBABILITY_SCALE_PPB
        {
            return Err(ProtocolError::InvalidQuantity);
        }
        #[cfg(not(feature = "prediction-market-guest"))]
        XOnlyPublicKey::from_slice(&self.trader_commitment)
            .map_err(|_| ProtocolError::InvalidSignature)?;
        #[cfg(feature = "prediction-market-guest")]
        VerifyingKey::from_bytes(&self.trader_commitment)
            .map_err(|_| ProtocolError::InvalidSignature)?;
        Ok(())
    }

    pub fn commitment(&self) -> Result<Hash32, ProtocolError> {
        self.validate()?;
        Ok(canonical_hash("ECX/prediction-market-order/v1", self))
    }
}

impl CanonicalEncode for PredictionMarketOrderV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(&self.market_id);
        out.extend_from_slice(&self.trader_commitment);
        out.extend_from_slice(&self.payout_script_sha256);
        put_u64(out, self.nonce);
        self.outcome.encode_to(out);
        self.side.encode_to(out);
        put_u64(out, self.outcome_quantity_units);
        put_u32(out, self.limit_probability_ppb);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SignedPredictionMarketOrderV1 {
    pub order: PredictionMarketOrderV1,
    pub signature: Signature64,
}

impl SignedPredictionMarketOrderV1 {
    #[cfg(any(not(feature = "prediction-market-guest"), test))]
    pub fn sign(
        order: PredictionMarketOrderV1,
        secret_key: &SecretKey,
    ) -> Result<Self, ProtocolError> {
        order.validate()?;
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, secret_key);
        let (public, _) = XOnlyPublicKey::from_keypair(&keypair);
        if public.serialize() != order.trader_commitment {
            return Err(ProtocolError::SigningKeyMismatch);
        }
        let message = Message::from_digest_slice(&order.commitment()?)
            .map_err(|_| ProtocolError::InvalidSignature)?;
        let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);
        Ok(Self {
            order,
            signature: Signature64(*signature.as_ref()),
        })
    }

    pub fn verify(&self) -> Result<(), ProtocolError> {
        self.order.validate()?;
        #[cfg(not(feature = "prediction-market-guest"))]
        {
            let public = XOnlyPublicKey::from_slice(&self.order.trader_commitment)
                .map_err(|_| ProtocolError::InvalidSignature)?;
            let signature = schnorr::Signature::from_slice(&self.signature.0)
                .map_err(|_| ProtocolError::InvalidSignature)?;
            let message = Message::from_digest_slice(&self.order.commitment()?)
                .map_err(|_| ProtocolError::InvalidSignature)?;
            return Secp256k1::verification_only()
                .verify_schnorr(&signature, &message, &public)
                .map_err(|_| ProtocolError::InvalidSignature);
        }
        #[cfg(feature = "prediction-market-guest")]
        {
            let public = VerifyingKey::from_bytes(&self.order.trader_commitment)
                .map_err(|_| ProtocolError::InvalidSignature)?;
            let signature = K256Signature::try_from(self.signature.0.as_slice())
                .map_err(|_| ProtocolError::InvalidSignature)?;
            // libsecp256k1's BIP340 API signs the supplied 32-byte protocol
            // commitment directly. `Verifier::verify` would SHA256 it again;
            // the raw interface is the matching BIP340 operation here.
            public
                .verify_raw(&self.order.commitment()?, &signature)
                .map_err(|_| ProtocolError::InvalidSignature)
        }
    }
}

impl CanonicalEncode for SignedPredictionMarketOrderV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.order.encode_to(out);
        self.signature.encode_to(out);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PredictionMarketTransitionV1 {
    pub prior_state_commitment: Hash32,
    pub successor_state_commitment: Hash32,
    pub order_commitment: Hash32,
    /// Positive for collateral deposited, negative for collateral redeemed.
    pub collateral_delta_units: i128,
    pub outcome_quantity_units: u64,
    pub post_trade_yes_probability_ppb: u32,
    pub parent_mtp: u64,
}

impl CanonicalEncode for PredictionMarketTransitionV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.prior_state_commitment);
        out.extend_from_slice(&self.successor_state_commitment);
        out.extend_from_slice(&self.order_commitment);
        put_i128(out, self.collateral_delta_units);
        put_u64(out, self.outcome_quantity_units);
        put_u32(out, self.post_trade_yes_probability_ppb);
        put_u64(out, self.parent_mtp);
    }
}

impl PredictionMarketTransitionV1 {
    pub fn commitment(&self) -> Hash32 {
        canonical_hash("ECX/prediction-market-transition/v1", self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PredictionMarketProofInputV1 {
    pub chain_id: Hash32,
    pub transaction_id: Hash32,
    pub configuration: PredictionMarketConfigV1,
    pub prior_state: PredictionMarketStateV1,
    pub accounts: Vec<PredictionMarketAccountV1>,
    pub signed_order: SignedPredictionMarketOrderV1,
    pub parent_mtp: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PredictionMarketPublicValuesV1 {
    pub version: u32,
    pub chain_id: Hash32,
    pub configuration_hash: Hash32,
    pub market_id: Hash32,
    pub prior_state_commitment: Hash32,
    pub successor_state_commitment: Hash32,
    pub order_commitment: Hash32,
    pub transition_commitment: Hash32,
    pub transaction_id: Hash32,
    /// Signed-order-bound sell destination. For buys this remains committed but unused.
    pub payout_script_sha256: Hash32,
    /// Exact collateral output required for a sell; zero for a buy.
    pub payout_amount_units: u64,
    pub parent_mtp: u64,
    pub collateral_delta_units: i128,
    pub outcome_quantity_units: u64,
    pub post_trade_yes_probability_ppb: u32,
}

impl CanonicalEncode for PredictionMarketPublicValuesV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u32(out, self.version);
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(&self.configuration_hash);
        out.extend_from_slice(&self.market_id);
        out.extend_from_slice(&self.prior_state_commitment);
        out.extend_from_slice(&self.successor_state_commitment);
        out.extend_from_slice(&self.order_commitment);
        out.extend_from_slice(&self.transition_commitment);
        out.extend_from_slice(&self.transaction_id);
        out.extend_from_slice(&self.payout_script_sha256);
        put_u64(out, self.payout_amount_units);
        put_u64(out, self.parent_mtp);
        put_i128(out, self.collateral_delta_units);
        put_u64(out, self.outcome_quantity_units);
        put_u32(out, self.post_trade_yes_probability_ppb);
    }
}

pub fn execute_prediction_market_proof_v1(
    input: &PredictionMarketProofInputV1,
) -> Result<(PredictionMarketStateV1, PredictionMarketPublicValuesV1), ProtocolError> {
    if input.chain_id == [0; 32] || input.transaction_id == [0; 32] {
        return Err(ProtocolError::InvalidMarket);
    }
    input.signed_order.verify()?;
    if input.signed_order.order.chain_id != input.chain_id
        || input.signed_order.order.market_id != input.configuration.market_id
    {
        return Err(ProtocolError::InvalidMarket);
    }
    let configuration_hash = input.configuration.commitment()?;
    let (successor, _, transition) = apply_prediction_market_order_v1(
        &input.configuration,
        &input.prior_state,
        &input.accounts,
        &input.signed_order.order,
        input.parent_mtp,
    )?;
    let public = PredictionMarketPublicValuesV1 {
        version: PREDICTION_MARKET_PUBLIC_VALUES_VERSION_V1,
        chain_id: input.chain_id,
        configuration_hash,
        market_id: input.configuration.market_id,
        prior_state_commitment: transition.prior_state_commitment,
        successor_state_commitment: transition.successor_state_commitment,
        order_commitment: transition.order_commitment,
        transition_commitment: transition.commitment(),
        transaction_id: input.transaction_id,
        payout_script_sha256: input.signed_order.order.payout_script_sha256,
        payout_amount_units: if transition.collateral_delta_units < 0 {
            u64::try_from(-transition.collateral_delta_units)
                .map_err(|_| ProtocolError::ArithmeticOverflow)?
        } else {
            0
        },
        parent_mtp: input.parent_mtp,
        collateral_delta_units: transition.collateral_delta_units,
        outcome_quantity_units: transition.outcome_quantity_units,
        post_trade_yes_probability_ppb: transition.post_trade_yes_probability_ppb,
    };
    debug_assert_eq!(
        public.canonical_bytes().len(),
        PREDICTION_MARKET_PUBLIC_VALUES_BYTES_V1
    );
    Ok((successor, public))
}

pub fn apply_prediction_market_order_v1(
    config: &PredictionMarketConfigV1,
    prior: &PredictionMarketStateV1,
    accounts: &[PredictionMarketAccountV1],
    order: &PredictionMarketOrderV1,
    parent_mtp: u64,
) -> Result<
    (
        PredictionMarketStateV1,
        Vec<PredictionMarketAccountV1>,
        PredictionMarketTransitionV1,
    ),
    ProtocolError,
> {
    prior.validate(config)?;
    order.validate()?;
    if order.market_id != config.market_id {
        return Err(ProtocolError::InvalidMarket);
    }
    if prediction_market_account_root_v1(accounts)? != prior.account_state_root {
        return Err(ProtocolError::StateRootMismatch);
    }
    let mut successor_accounts = accounts.to_vec();
    let account_index = successor_accounts
        .iter()
        .position(|account| account.trader_commitment == order.trader_commitment)
        .ok_or(ProtocolError::InsufficientCollateral)?;
    let account = successor_accounts[account_index];
    if account.nonce != order.nonce {
        return Err(ProtocolError::InvalidNonce);
    }
    if parent_mtp < prior.last_parent_mtp || parent_mtp >= config.expiry_parent_mtp {
        return Err(ProtocolError::InvalidOracleSchedule);
    }
    let invariant = u128::from(prior.yes_reserve_units) * u128::from(prior.no_reserve_units);
    let (target, opposite) = match order.outcome {
        BinaryOutcomeV1::Yes => (prior.yes_reserve_units, prior.no_reserve_units),
        BinaryOutcomeV1::No => (prior.no_reserve_units, prior.yes_reserve_units),
    };
    let (next_target, next_opposite, collateral_delta, volume) = match order.side {
        PredictionMarketSideV1::Buy => {
            let collateral =
                minimum_buy_collateral(target, opposite, order.outcome_quantity_units, invariant)?;
            let next_target = target
                .checked_add(collateral)
                .and_then(|v| v.checked_sub(order.outcome_quantity_units))
                .ok_or(ProtocolError::ArithmeticOverflow)?;
            let next_opposite = opposite
                .checked_add(collateral)
                .ok_or(ProtocolError::ArithmeticOverflow)?;
            if collateral > account.available_collateral_units {
                return Err(ProtocolError::InsufficientCollateral);
            }
            (
                next_target,
                next_opposite,
                i128::from(collateral),
                collateral,
            )
        }
        PredictionMarketSideV1::Sell => {
            let payout =
                maximum_sell_collateral(target, opposite, order.outcome_quantity_units, invariant)?;
            if payout == 0 || payout > prior.collateral_locked_units {
                return Err(ProtocolError::InsufficientCollateral);
            }
            let next_target = target
                .checked_add(order.outcome_quantity_units)
                .and_then(|v| v.checked_sub(payout))
                .ok_or(ProtocolError::ArithmeticOverflow)?;
            let next_opposite = opposite
                .checked_sub(payout)
                .ok_or(ProtocolError::ArithmeticOverflow)?;
            (next_target, next_opposite, -i128::from(payout), payout)
        }
    };
    let (yes_reserve_units, no_reserve_units) = match order.outcome {
        BinaryOutcomeV1::Yes => (next_target, next_opposite),
        BinaryOutcomeV1::No => (next_opposite, next_target),
    };
    let collateral_locked_units = if collateral_delta >= 0 {
        prior
            .collateral_locked_units
            .checked_add(collateral_delta as u64)
    } else {
        prior
            .collateral_locked_units
            .checked_sub((-collateral_delta) as u64)
    }
    .ok_or(ProtocolError::ArithmeticOverflow)?;
    let mut successor_account = account;
    successor_account.nonce = successor_account
        .nonce
        .checked_add(1)
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    if collateral_delta >= 0 {
        successor_account.available_collateral_units = successor_account
            .available_collateral_units
            .checked_sub(collateral_delta as u64)
            .ok_or(ProtocolError::InsufficientCollateral)?;
    } else {
        successor_account.available_collateral_units = successor_account
            .available_collateral_units
            .checked_add((-collateral_delta) as u64)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
    }
    let shares = match order.outcome {
        BinaryOutcomeV1::Yes => &mut successor_account.yes_shares_units,
        BinaryOutcomeV1::No => &mut successor_account.no_shares_units,
    };
    *shares = match order.side {
        PredictionMarketSideV1::Buy => shares
            .checked_add(order.outcome_quantity_units)
            .ok_or(ProtocolError::ArithmeticOverflow)?,
        PredictionMarketSideV1::Sell => shares
            .checked_sub(order.outcome_quantity_units)
            .ok_or(ProtocolError::InsufficientCollateral)?,
    };
    successor_accounts[account_index] = successor_account;
    let account_state_root = prediction_market_account_root_v1(&successor_accounts)?;
    let total_yes = successor_accounts.iter().try_fold(0u128, |sum, item| {
        sum.checked_add(u128::from(item.yes_shares_units))
            .ok_or(ProtocolError::ArithmeticOverflow)
    })?;
    let total_no = successor_accounts.iter().try_fold(0u128, |sum, item| {
        sum.checked_add(u128::from(item.no_shares_units))
            .ok_or(ProtocolError::ArithmeticOverflow)
    })?;
    if u128::from(collateral_locked_units) < total_yes
        || u128::from(collateral_locked_units) < total_no
    {
        return Err(ProtocolError::ConservationViolation);
    }
    let successor = PredictionMarketStateV1 {
        version: prior.version,
        configuration_hash: prior.configuration_hash,
        account_state_root,
        yes_reserve_units,
        no_reserve_units,
        collateral_locked_units,
        cumulative_volume_units: prior
            .cumulative_volume_units
            .checked_add(u128::from(volume))
            .ok_or(ProtocolError::ArithmeticOverflow)?,
        sequence: prior
            .sequence
            .checked_add(1)
            .ok_or(ProtocolError::ArithmeticOverflow)?,
        last_parent_mtp: parent_mtp,
    };
    successor.validate(config)?;
    let post_yes = successor.yes_probability_ppb()?;
    let outcome_probability = match order.outcome {
        BinaryOutcomeV1::Yes => post_yes,
        BinaryOutcomeV1::No => (PROBABILITY_SCALE_PPB as u32)
            .checked_sub(post_yes)
            .ok_or(ProtocolError::ArithmeticOverflow)?,
    };
    let limit_ok = match order.side {
        PredictionMarketSideV1::Buy => outcome_probability <= order.limit_probability_ppb,
        PredictionMarketSideV1::Sell => outcome_probability >= order.limit_probability_ppb,
    };
    if !limit_ok {
        return Err(ProtocolError::InvalidRate);
    }
    let transition = PredictionMarketTransitionV1 {
        prior_state_commitment: prior.commitment(config)?,
        successor_state_commitment: successor.commitment(config)?,
        order_commitment: order.commitment()?,
        collateral_delta_units: collateral_delta,
        outcome_quantity_units: order.outcome_quantity_units,
        post_trade_yes_probability_ppb: post_yes,
        parent_mtp,
    };
    Ok((successor, successor_accounts, transition))
}

fn minimum_buy_collateral(
    target: u64,
    opposite: u64,
    quantity: u64,
    invariant: u128,
) -> Result<u64, ProtocolError> {
    let maximum = u64::MAX.saturating_sub(target.max(opposite));
    let valid = |collateral: u64| -> bool {
        let Some(next_target) = target
            .checked_add(collateral)
            .and_then(|v| v.checked_sub(quantity))
        else {
            return false;
        };
        let Some(next_opposite) = opposite.checked_add(collateral) else {
            return false;
        };
        next_target > 0 && u128::from(next_target) * u128::from(next_opposite) >= invariant
    };
    if !valid(maximum) {
        return Err(ProtocolError::ArithmeticOverflow);
    }
    let mut low = 0u64;
    let mut high = maximum;
    while low < high {
        let middle = low + (high - low) / 2;
        if valid(middle) {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    Ok(low)
}

fn maximum_sell_collateral(
    target: u64,
    opposite: u64,
    quantity: u64,
    invariant: u128,
) -> Result<u64, ProtocolError> {
    let target_with_order = target
        .checked_add(quantity)
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    let mut low = 0u64;
    let mut high = opposite.min(target_with_order).saturating_sub(1);
    while low < high {
        let middle = low + (high - low + 1) / 2;
        let product = u128::from(target_with_order - middle) * u128::from(opposite - middle);
        if product >= invariant {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    Ok(low)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> SecretKey {
        SecretKey::from_slice(&[3; 32]).unwrap()
    }
    fn trader() -> Hash32 {
        let pair = Keypair::from_secret_key(&Secp256k1::new(), &secret());
        XOnlyPublicKey::from_keypair(&pair).0.serialize()
    }

    fn fixture() -> (
        PredictionMarketConfigV1,
        PredictionMarketStateV1,
        Vec<PredictionMarketAccountV1>,
    ) {
        let config = PredictionMarketConfigV1 {
            market_id: [1; 32],
            collateral_asset: [2; 32],
            yes_asset: [3; 32],
            no_asset: [4; 32],
            pair_id: *b"ECX-USDD-SPOT\0\0\0",
            strike_price_ticks: 50_000_000,
            expiry_parent_mtp: 2_000,
        };
        let accounts = vec![PredictionMarketAccountV1 {
            trader_commitment: trader(),
            available_collateral_units: 2_000_000,
            yes_shares_units: 0,
            no_shares_units: 0,
            nonce: 12,
        }];
        let state = PredictionMarketStateV1 {
            version: 1,
            configuration_hash: config.commitment().unwrap(),
            account_state_root: prediction_market_account_root_v1(&accounts).unwrap(),
            yes_reserve_units: 1_000_000,
            no_reserve_units: 1_000_000,
            collateral_locked_units: 1_000_000,
            cumulative_volume_units: 0,
            sequence: 7,
            last_parent_mtp: 1_000,
        };
        (config, state, accounts)
    }

    fn order(
        side: PredictionMarketSideV1,
        outcome: BinaryOutcomeV1,
        quantity: u64,
    ) -> PredictionMarketOrderV1 {
        PredictionMarketOrderV1 {
            version: 1,
            chain_id: [7; 32],
            market_id: [1; 32],
            trader_commitment: trader(),
            payout_script_sha256: [9; 32],
            nonce: 12,
            outcome,
            side,
            outcome_quantity_units: quantity,
            limit_probability_ppb: 999_999_999,
        }
    }

    #[test]
    fn buying_yes_is_fully_collateralized_and_increases_yes_probability() {
        let (config, state, accounts) = fixture();
        let (next, next_accounts, receipt) = apply_prediction_market_order_v1(
            &config,
            &state,
            &accounts,
            &order(PredictionMarketSideV1::Buy, BinaryOutcomeV1::Yes, 100_000),
            1_001,
        )
        .unwrap();
        assert!(next.yes_probability_ppb().unwrap() > state.yes_probability_ppb().unwrap());
        assert!(receipt.collateral_delta_units > 0);
        assert_eq!(next.sequence, state.sequence + 1);
        assert_eq!(next_accounts[0].yes_shares_units, 100_000);
        assert_eq!(
            next.account_state_root,
            prediction_market_account_root_v1(&next_accounts).unwrap()
        );
        assert!(
            u128::from(next.yes_reserve_units) * u128::from(next.no_reserve_units)
                >= u128::from(state.yes_reserve_units) * u128::from(state.no_reserve_units)
        );
    }

    #[test]
    fn selling_owned_yes_redeems_collateral_and_reduces_yes_probability() {
        let (config, state, accounts) = fixture();
        let (bought, bought_accounts, _) = apply_prediction_market_order_v1(
            &config,
            &state,
            &accounts,
            &order(PredictionMarketSideV1::Buy, BinaryOutcomeV1::Yes, 100_000),
            1_001,
        )
        .unwrap();
        let mut sell = order(PredictionMarketSideV1::Sell, BinaryOutcomeV1::Yes, 100_000);
        sell.nonce = 13;
        sell.limit_probability_ppb = 1;
        let (sold, sold_accounts, receipt) =
            apply_prediction_market_order_v1(&config, &bought, &bought_accounts, &sell, 1_002)
                .unwrap();
        assert!(receipt.collateral_delta_units < 0);
        assert!(sold.yes_probability_ppb().unwrap() < bought.yes_probability_ppb().unwrap());
        assert!(sold.collateral_locked_units < bought.collateral_locked_units);
        assert_eq!(sold_accounts[0].yes_shares_units, 0);
    }

    #[test]
    fn limit_and_expiry_fail_closed_without_a_successor() {
        let (config, state, accounts) = fixture();
        let mut limited = order(PredictionMarketSideV1::Buy, BinaryOutcomeV1::Yes, 500_000);
        limited.limit_probability_ppb = 500_000_000;
        assert_eq!(
            apply_prediction_market_order_v1(&config, &state, &accounts, &limited, 1_001),
            Err(ProtocolError::InvalidRate)
        );
        assert_eq!(
            apply_prediction_market_order_v1(
                &config,
                &state,
                &accounts,
                &order(PredictionMarketSideV1::Buy, BinaryOutcomeV1::Yes, 1),
                2_000
            ),
            Err(ProtocolError::InvalidOracleSchedule)
        );
    }

    #[test]
    fn commitments_bind_order_direction_and_successor() {
        let (config, state, accounts) = fixture();
        let buy_yes = order(PredictionMarketSideV1::Buy, BinaryOutcomeV1::Yes, 10_000);
        let buy_no = order(PredictionMarketSideV1::Buy, BinaryOutcomeV1::No, 10_000);
        assert_ne!(buy_yes.commitment().unwrap(), buy_no.commitment().unwrap());
        let mut redirected = buy_yes;
        redirected.payout_script_sha256 = [10; 32];
        assert_ne!(
            buy_yes.commitment().unwrap(),
            redirected.commitment().unwrap()
        );
        let (_, _, yes_receipt) =
            apply_prediction_market_order_v1(&config, &state, &accounts, &buy_yes, 1_001).unwrap();
        let (_, _, no_receipt) =
            apply_prediction_market_order_v1(&config, &state, &accounts, &buy_no, 1_001).unwrap();
        assert_ne!(
            yes_receipt.successor_state_commitment,
            no_receipt.successor_state_commitment
        );
        assert_ne!(yes_receipt.commitment(), no_receipt.commitment());
        assert_eq!(
            to_hex(&config.commitment().unwrap()),
            "42de97b0bb5deaf1302e178fc6b9de4ebf87c1be4942a2e91be3a9439ebee6ed"
        );
        assert_eq!(
            to_hex(&trader()),
            "531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337"
        );
        assert_eq!(
            to_hex(&state.account_state_root),
            "2c149c8f91cddb59fe2e3933ac3c3d649d27f925b24c1a6adb4475c89caee6ec"
        );
        assert_eq!(
            to_hex(&state.commitment(&config).unwrap()),
            "e63f2cc80d692b69ef2149846147d00cdf269628b255a40a4012b5c8ce831c55"
        );
        assert_eq!(
            to_hex(&buy_yes.commitment().unwrap()),
            "e0798a56c5320dfa705503a16f12a6db74c93f8f0e540c48d8d2bb158ff875c0"
        );
        assert_eq!(
            to_hex(&yes_receipt.successor_state_commitment),
            "ec77571909cb33e835ef2b3ce9d6fcdda3d3a41a30f9dc8f8c0913debc7260ba"
        );
        assert_eq!(
            to_hex(&yes_receipt.commitment()),
            "2821985f0c1c0573f6fa9e3ae97053e3116e9a206a91321d55675cb6ea1f4ae7"
        );
    }

    #[test]
    fn account_root_balance_nonce_and_inventory_are_enforced() {
        let (config, state, accounts) = fixture();
        let mut changed = accounts.clone();
        changed[0].available_collateral_units -= 1;
        assert_eq!(
            apply_prediction_market_order_v1(
                &config,
                &state,
                &changed,
                &order(PredictionMarketSideV1::Buy, BinaryOutcomeV1::Yes, 1),
                1_001
            ),
            Err(ProtocolError::StateRootMismatch)
        );
        let sell = order(PredictionMarketSideV1::Sell, BinaryOutcomeV1::Yes, 1);
        assert_eq!(
            apply_prediction_market_order_v1(&config, &state, &accounts, &sell, 1_001),
            Err(ProtocolError::InsufficientCollateral)
        );
        let mut replay = order(PredictionMarketSideV1::Buy, BinaryOutcomeV1::Yes, 1);
        replay.nonce += 1;
        assert_eq!(
            apply_prediction_market_order_v1(&config, &state, &accounts, &replay, 1_001),
            Err(ProtocolError::InvalidNonce)
        );
    }

    #[test]
    fn proof_public_values_are_exact_length_and_bind_chain_and_transaction() {
        let (config, state, accounts) = fixture();
        let signed_order = SignedPredictionMarketOrderV1::sign(
            order(PredictionMarketSideV1::Buy, BinaryOutcomeV1::Yes, 10_000),
            &secret(),
        )
        .unwrap();
        let input = PredictionMarketProofInputV1 {
            chain_id: [7; 32],
            transaction_id: [8; 32],
            configuration: config,
            prior_state: state,
            accounts,
            signed_order,
            parent_mtp: 1_001,
        };
        let (_, values) = execute_prediction_market_proof_v1(&input).unwrap();
        assert_eq!(
            values.canonical_bytes().len(),
            PREDICTION_MARKET_PUBLIC_VALUES_BYTES_V1
        );
        assert_eq!(values.payout_script_sha256, [9; 32]);
        assert_eq!(values.payout_amount_units, 0);
        let mut changed = input.clone();
        changed.transaction_id = [10; 32];
        let (_, changed_values) = execute_prediction_market_proof_v1(&changed).unwrap();
        assert_ne!(values.canonical_bytes(), changed_values.canonical_bytes());
        let mut invalid = input.clone();
        invalid.signed_order.signature.0[0] ^= 1;
        assert_eq!(
            execute_prediction_market_proof_v1(&invalid),
            Err(ProtocolError::InvalidSignature)
        );
    }

    fn to_hex(value: &Hash32) -> String {
        value.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
