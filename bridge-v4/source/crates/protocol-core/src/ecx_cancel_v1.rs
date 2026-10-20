//! ECX-domain single-order cancellation. The enclosing successor must bind
//! both source roots and commit both returned roots atomically.
use crate::codec::CanonicalEncode;
use crate::ecx_cash_account_v1::{EcxAccountDomainV1, EcxAccountOpeningV1, replace_ecx_account_leaf};
use crate::ecx_configuration_v1::EcxConfigurationV1;
use crate::ecx_order_v1::EcxAdmittedOrderV2;
use crate::hash::{Hash32, tagged_hash};
use crate::order::Signature64;
use crate::successor_action_v2::{SuccessorCancelOrderV2, sign_digest, verify_digest};
use crate::ProtocolError;
use secp256k1::SecretKey;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SignedEcxCancelV1 {
    pub domain: EcxAccountDomainV1,
    pub cancel: SuccessorCancelOrderV2,
    pub signature: Signature64,
}

fn digest(domain: EcxAccountDomainV1, cancel: &SuccessorCancelOrderV2) -> Result<Hash32, ProtocolError> {
    cancel.validate()?;
    if domain.chain_id == [0; 32] || domain.configuration_hash == [0; 32]
        || domain.collateral_asset == [0; 32] || cancel.chain_id != domain.chain_id
        || cancel.market != domain.market {
        return Err(ProtocolError::InvalidBondState);
    }
    let mut bytes = vec![1];
    bytes.extend_from_slice(&domain.configuration_hash);
    bytes.extend_from_slice(&domain.collateral_asset);
    cancel.encode_to(&mut bytes);
    Ok(tagged_hash("ECX/ecx-cancel-order/v1", &bytes))
}

impl SignedEcxCancelV1 {
    pub fn sign(domain: EcxAccountDomainV1, cancel: SuccessorCancelOrderV2, key: &SecretKey)
        -> Result<Self, ProtocolError> {
        let signature = sign_digest(digest(domain, &cancel)?, cancel.trader, key)?;
        Ok(Self { domain, cancel, signature })
    }
    pub fn verify(&self, expected: EcxAccountDomainV1) -> Result<(), ProtocolError> {
        if self.domain != expected { return Err(ProtocolError::InvalidBondState); }
        verify_digest(digest(expected, &self.cancel)?, self.cancel.trader, self.signature)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcxCancelledOrderV1 {
    pub accounts_root: Hash32,
    pub orders_root: Hash32,
    pub position: crate::incremental_state_v2::TraderLeafV2,
}

/// Removes exactly the signed order, consuming the current account nonce.
/// Cancellation transfers no cash, changes no position or generation, and
/// requires no oracle: subsequent withdrawal recomputes reserve independently.
pub fn stage_ecx_cancel_v1(
    accounts_root: Hash32, orders_root: Hash32, economics: EcxConfigurationV1,
    signed: &SignedEcxCancelV1, account: EcxAccountOpeningV1<'_>,
    order: &EcxAdmittedOrderV2, order_siblings: &[Hash32], height: u64,
) -> Result<EcxCancelledOrderV1, ProtocolError> {
    let domain = economics.account_domain()?;
    signed.verify(domain)?;
    let cancel = &signed.cancel;
    if height < cancel.valid_from_height || height > cancel.expires_at_height {
        return Err(ProtocolError::OrderNotLive);
    }
    if cancel.nonce != account.position.account_nonce {
        return Err(ProtocolError::InvalidNonce);
    }
    let key = order.signed.order_id()?;
    if cancel.trader != account.position.trader || order.signed.order.trader != cancel.trader
        || cancel.order_id != key || order.signed.order.nonce >= cancel.nonce
        || order.generation > account.position.order_generation {
        return Err(ProtocolError::InvalidBondState);
    }
    if crate::ecx_order_index_v1::order_root(domain, key, Some(order), order_siblings)? != orders_root {
        return Err(ProtocolError::InvalidMerkleProof);
    }
    let mut position = account.position.clone();
    position.account_nonce = position.account_nonce.checked_add(1).ok_or(ProtocolError::ArithmeticOverflow)?;
    let accounts_root = replace_ecx_account_leaf(accounts_root, domain, account.position,
        account.cash, &position, account.cash, economics.bounds, account.siblings)?;
    let orders_root = crate::ecx_order_index_v1::order_root(domain, key, None, order_siblings)?;
    Ok(EcxCancelledOrderV1 { accounts_root, orders_root, position })
}
