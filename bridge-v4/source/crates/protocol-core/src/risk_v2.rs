//! V2 order-level collateral commitment and direction-aware margin helpers.

use secp256k1::{schnorr, Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};

use crate::codec::{put_u32, put_u8, CanonicalEncode};
use crate::hash::{canonical_hash, Hash32};
use crate::order::{OrderId, Signature64};
use crate::risk::{notional, RiskParams};
use crate::types::{Amount, Position, Price, XOnlyKey};
use crate::ProtocolError;

pub const ALLOWED_INITIAL_MARGIN_BPS_V2: [u32; 5] = [10_000, 5_000, 3_334, 2_000, 1_000];

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OrderRiskCommitmentV2 {
    pub version: u8,
    /// Frozen V2 singleton configuration. The V1 order itself remains
    /// unchanged; this additive signature prevents its selected leverage from
    /// being replayed into another exchange deployment on the same chain.
    pub configuration_hash: Hash32,
    pub order_id: OrderId,
    pub trader: XOnlyKey,
    pub selected_initial_margin_bps: u32,
    pub signature: Signature64,
}

impl OrderRiskCommitmentV2 {
    pub const VERSION: u8 = 1;

    fn unsigned_digest(
        version: u8,
        configuration_hash: Hash32,
        order_id: OrderId,
        trader: XOnlyKey,
        selected_initial_margin_bps: u32,
    ) -> Hash32 {
        #[derive(Clone, Copy)]
        struct Unsigned {
            version: u8,
            configuration_hash: Hash32,
            order_id: OrderId,
            trader: XOnlyKey,
            selected_initial_margin_bps: u32,
        }
        impl CanonicalEncode for Unsigned {
            fn encode_to(&self, out: &mut Vec<u8>) {
                put_u8(out, self.version);
                out.extend_from_slice(&self.configuration_hash);
                out.extend_from_slice(&self.order_id);
                self.trader.encode_to(out);
                put_u32(out, self.selected_initial_margin_bps);
            }
        }
        canonical_hash(
            "ECX/order-risk-commitment/v2",
            &Unsigned {
                version,
                configuration_hash,
                order_id,
                trader,
                selected_initial_margin_bps,
            },
        )
    }

    pub fn sign(
        configuration_hash: Hash32,
        order_id: OrderId,
        trader: XOnlyKey,
        selected_initial_margin_bps: u32,
        secret_key: &SecretKey,
    ) -> Result<Self, ProtocolError> {
        if configuration_hash == [0; 32] {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        validate_selected_margin_bps(selected_initial_margin_bps, RiskParams::default())?;
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, secret_key);
        let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
        if xonly.serialize() != trader.0 {
            return Err(ProtocolError::SigningKeyMismatch);
        }
        let digest = Self::unsigned_digest(
            Self::VERSION,
            configuration_hash,
            order_id,
            trader,
            selected_initial_margin_bps,
        );
        let message =
            Message::from_digest_slice(&digest).map_err(|_| ProtocolError::InvalidSignature)?;
        let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);
        Ok(Self {
            version: Self::VERSION,
            configuration_hash,
            order_id,
            trader,
            selected_initial_margin_bps,
            signature: Signature64(*signature.as_ref()),
        })
    }

    pub fn verify(&self, params: RiskParams) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION
            || self.configuration_hash == [0; 32]
            || self.order_id == [0; 32]
        {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        validate_selected_margin_bps(self.selected_initial_margin_bps, params)?;
        let key = XOnlyPublicKey::from_slice(&self.trader.0)
            .map_err(|_| ProtocolError::InvalidSignature)?;
        let signature = schnorr::Signature::from_slice(&self.signature.0)
            .map_err(|_| ProtocolError::InvalidSignature)?;
        let message = Message::from_digest_slice(&Self::unsigned_digest(
            self.version,
            self.configuration_hash,
            self.order_id,
            self.trader,
            self.selected_initial_margin_bps,
        ))
        .map_err(|_| ProtocolError::InvalidSignature)?;
        Secp256k1::verification_only()
            .verify_schnorr(&signature, &message, &key)
            .map_err(|_| ProtocolError::InvalidSignature)
    }
}

impl CanonicalEncode for OrderRiskCommitmentV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.configuration_hash);
        out.extend_from_slice(&self.order_id);
        self.trader.encode_to(out);
        put_u32(out, self.selected_initial_margin_bps);
        self.signature.encode_to(out);
    }
}

pub fn validate_selected_margin_bps(
    selected_initial_margin_bps: u32,
    params: RiskParams,
) -> Result<(), ProtocolError> {
    params.validate()?;
    if !ALLOWED_INITIAL_MARGIN_BPS_V2.contains(&selected_initial_margin_bps)
        || selected_initial_margin_bps < params.initial_margin_bps
    {
        return Err(ProtocolError::InvalidRate);
    }
    Ok(())
}

pub fn creates_directional_risk(old: Position, next: Position) -> bool {
    next.size != 0
        && (old.size == 0
            || old.size.signum() != next.size.signum()
            || next.size.unsigned_abs() > old.size.unsigned_abs())
}

pub fn required_margin_bps_v2(
    position: &Position,
    mark: Price,
    margin_bps: u32,
) -> Result<Amount, ProtocolError> {
    if margin_bps == 0 || margin_bps > 10_000 {
        return Err(ProtocolError::InvalidRate);
    }
    let notional = u128::try_from(notional(mark, position.size.unsigned_abs())?.0)
        .map_err(|_| ProtocolError::ArithmeticOverflow)?;
    let product = notional
        .checked_mul(u128::from(margin_bps))
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    let margin = product
        .checked_add(9_999)
        .ok_or(ProtocolError::ArithmeticOverflow)?
        / 10_000;
    Ok(Amount(
        i128::try_from(margin).map_err(|_| ProtocolError::ArithmeticOverflow)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crossing_direction_is_new_risk_even_when_absolute_size_falls() {
        let old = Position {
            size: 10,
            entry_price: 1,
            last_funding_index: 0,
        };
        let crossed = Position {
            size: -5,
            entry_price: 1,
            last_funding_index: 0,
        };
        assert!(creates_directional_risk(old, crossed));
    }

    #[test]
    fn only_exact_ui_leverage_steps_are_admitted() {
        let params = RiskParams::default();
        for bps in ALLOWED_INITIAL_MARGIN_BPS_V2 {
            validate_selected_margin_bps(bps, params).unwrap();
        }
        assert_eq!(
            validate_selected_margin_bps(999, params),
            Err(ProtocolError::InvalidRate)
        );
    }

    #[test]
    fn selected_leverage_signature_is_singleton_configuration_bound() {
        let secret = SecretKey::from_slice(&[41; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
        let (public, _) = XOnlyPublicKey::from_keypair(&keypair);
        let mut commitment = OrderRiskCommitmentV2::sign(
            [42; 32],
            [43; 32],
            XOnlyKey(public.serialize()),
            2_000,
            &secret,
        )
        .unwrap();
        commitment.verify(RiskParams::default()).unwrap();
        commitment.configuration_hash[0] ^= 1;
        assert_eq!(
            commitment.verify(RiskParams::default()),
            Err(ProtocolError::InvalidSignature)
        );
    }
}
