//! Domain-separated ECX withdrawal consent and account debit staging.
//! Complete-book reservations are checked here; source inclusion, vault
//! conservation and exact recipient output belong to the enclosing successor.
use crate::codec::CanonicalEncode;
use crate::ecx_cash_account_v1::EcxAccountDomainV1;
use crate::hash::{tagged_hash, Hash32};
use crate::order::Signature64;
use crate::successor_action_v2::{sign_digest, verify_digest, SuccessorWithdrawalRequestV2};
use crate::ProtocolError;
use secp256k1::SecretKey;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcxWithdrawalAccountUpdateV1 {
    pub accounts_root: Hash32,
    pub position: crate::incremental_state_v2::TraderLeafV2,
    pub cash: crate::ecx_cash_account_v1::EcxCashAccountV1,
}

/// Complete book opening. The expected root must be pinned by the enclosing
/// authenticated exchange state, never chosen from the supplied records.
#[derive(Clone, Copy)]
pub struct EcxWithdrawalOrdersV1<'a> {
    pub root: Hash32,
    pub records: &'a [&'a crate::ecx_order_v1::EcxAdmittedOrderV2],
}

/// Stage signature, exact source nonce, maturity, position margin, complete-book
/// aggregate collateral reservation and account
/// membership as one computed update. Does not cancel orders or authorize a
/// transaction. The outer successor MUST pin the expected orders root,
/// authenticated oracle/funding context, and exact recipient/vault outputs
/// before committing. The current economics configuration has no additional
/// account-withdrawal delay field: this function enforces signed not-before.
/// BIP300 withdrawal expiry is a separate rule, not an account maturity delay.
pub fn stage_ecx_withdrawal_account_v1(
    source_root: Hash32,
    economics: crate::ecx_configuration_v1::EcxConfigurationV1,
    signed: &SignedEcxWithdrawalV1,
    account: crate::ecx_cash_account_v1::EcxAccountOpeningV1<'_>,
    height: u64,
    low: crate::types::Price,
    high: crate::types::Price,
    funding: i128,
    orders: EcxWithdrawalOrdersV1<'_>,
) -> Result<EcxWithdrawalAccountUpdateV1, ProtocolError> {
    let domain = economics.account_domain()?;
    signed.verify(domain)?;
    let request = &signed.request;
    if account.position.trader != request.trader
        || request.trader == economics.clearing_account
        || request.trader == economics.insurance_account
    {
        return Err(ProtocolError::InvalidBondState);
    }
    if account.position.account_nonce != request.nonce {
        return Err(ProtocolError::InvalidNonce);
    }
    if height < request.not_before_height {
        return Err(ProtocolError::TransitionMismatch("withdrawal context"));
    }
    // Authenticate against the SOURCE nonce: incrementing it first could make
    // an unadmitted order appear to have consumed a nonce.
    let reserve = crate::ecx_order_index_v1::ecx_outstanding_order_reserve_atoms_v1(
        orders.root, economics, orders.records, account.position, account.cash,
        height, low, high, funding,
    )?;
    let mut position = account.position.clone();
    position.account_nonce = position.account_nonce.checked_add(1)
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    let cash = account.cash.checked_margin_withdrawal(
        request.amount, &position, economics.cash_valuation_scale, low, high,
        funding, position.selected_initial_margin_bps.max(economics.risk.initial_margin_bps),
        economics.bounds,
    )?;
    // Reserve already includes fees, margin and fractional debt. Compare it
    // with physical post-debit cash; never debit it or add fictitious claims.
    if crate::incremental_state_v2::Int256V2::from_u128(u128::from(cash.balance().0)) < reserve {
        return Err(ProtocolError::InsufficientCollateral);
    }
    let accounts_root = crate::ecx_cash_account_v1::replace_ecx_account_leaf(
        source_root, domain, account.position, account.cash, &position, &cash,
        economics.bounds, account.siblings,
    )?;
    Ok(EcxWithdrawalAccountUpdateV1 { accounts_root, position, cash })
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SignedEcxWithdrawalV1 {
    pub domain: EcxAccountDomainV1,
    pub request: SuccessorWithdrawalRequestV2,
    pub signature: Signature64,
}

fn digest(domain: EcxAccountDomainV1, request: &SuccessorWithdrawalRequestV2)
    -> Result<Hash32, ProtocolError>
{
    request.validate()?;
    if domain.chain_id == [0; 32] || domain.configuration_hash == [0; 32]
        || domain.collateral_asset == [0; 32] || request.chain_id != domain.chain_id
        || request.destination_script_hash == [0; 32]
    {
        return Err(ProtocolError::InvalidBondState);
    }
    let mut bytes = vec![1];
    bytes.extend_from_slice(&domain.configuration_hash);
    bytes.extend_from_slice(&domain.collateral_asset);
    domain.market.encode_to(&mut bytes);
    // Includes chain, owner, nonce, amount, recipient and requested/maturity heights.
    request.encode_to(&mut bytes);
    Ok(tagged_hash("ECX/ecx-collateral-withdrawal/v1", &bytes))
}

impl SignedEcxWithdrawalV1 {
    pub fn sign(domain: EcxAccountDomainV1, request: SuccessorWithdrawalRequestV2,
        key: &SecretKey) -> Result<Self, ProtocolError>
    {
        let signature = sign_digest(digest(domain, &request)?, request.trader, key)?;
        Ok(Self { domain, request, signature })
    }

    /// Expected domain must come from authenticated configuration, never this request.
    pub fn verify(&self, expected: EcxAccountDomainV1) -> Result<(), ProtocolError> {
        if self.domain != expected { return Err(ProtocolError::InvalidBondState); }
        verify_digest(digest(self.domain, &self.request)?, self.request.trader, self.signature)
    }

    pub fn request_id(&self) -> Result<Hash32, ProtocolError> {
        digest(self.domain, &self.request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::successor_action_v2::SuccessorSignedWithdrawalRequestV2;
    use crate::types::{XOnlyKey, ECX_USDD_MARKET};
    use secp256k1::{Keypair, Secp256k1};

    #[test]
    fn ecx_withdrawal_binds_all_terms_and_rejects_legacy_consent() {
        let key = SecretKey::from_slice(&[7; 32]).unwrap();
        let domain = EcxAccountDomainV1 { chain_id: [1; 32], market: ECX_USDD_MARKET,
            configuration_hash: [2; 32], collateral_asset: [3; 32] };
        let request = SuccessorWithdrawalRequestV2 {
            version: 2, chain_id: domain.chain_id,
            trader: XOnlyKey(Keypair::from_secret_key(&Secp256k1::new(), &key)
                .x_only_public_key().0.serialize()),
            nonce: 4, amount: 5, destination_script_hash: [6; 32],
            requested_height: 10, not_before_height: 154,
        };
        let signed = SignedEcxWithdrawalV1::sign(domain, request.clone(), &key).unwrap();
        signed.verify(domain).unwrap();
        let legacy = SuccessorSignedWithdrawalRequestV2::sign(request.clone(), &key).unwrap();
        let mut changed = signed.clone();
        changed.signature = legacy.signature;
        assert!(changed.verify(domain).is_err());
        assert!(SuccessorSignedWithdrawalRequestV2 {
            request: request.clone(), signature: signed.signature }.verify().is_err());
        for field in 0..10 {
            let mut changed = signed.clone();
            match field {
                0 => changed.request.nonce += 1,
                1 => changed.request.amount += 1,
                2 => changed.request.destination_script_hash[0] ^= 1,
                3 => changed.request.requested_height += 1,
                4 => changed.request.not_before_height += 1,
                5 => changed.domain.configuration_hash[0] ^= 1,
                6 => changed.domain.collateral_asset[0] ^= 1,
                7 => changed.domain.market.0[0] ^= 1,
                8 => changed.request.trader = XOnlyKey(Keypair::from_secret_key(
                    &Secp256k1::new(), &SecretKey::from_slice(&[8; 32]).unwrap())
                    .x_only_public_key().0.serialize()),
                _ => { changed.domain.chain_id[0] ^= 1;
                    changed.request.chain_id = changed.domain.chain_id; },
            }
            assert!(changed.verify(domain).is_err());
            // Even a caller-selected changed domain cannot make the old signature valid.
            assert!(changed.verify(changed.domain).is_err());
            assert_ne!(signed.request_id().unwrap(), changed.request_id().unwrap());
        }
        assert!(SignedEcxWithdrawalV1::sign(domain, request.clone(),
            &SecretKey::from_slice(&[8; 32]).unwrap()).is_err());
        let mut zero = request;
        zero.amount = 0;
        assert!(SignedEcxWithdrawalV1::sign(domain, zero, &key).is_err());
    }
}
