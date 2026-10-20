//! Shared transaction/account decoding; no authorization or inclusion claim.
use ecx_protocol_core::{Hash32, TraderLeafV2,
    ecx_cash_account_v1::{EcxAccountOpeningV1, EcxCashAccountV1}};
use crate::{proof_v2::ProofErrorV2, ecx_match_input_v1::EcxOwnedAccountV1,
    ecx_successor_state_v1::EcxSuccessorStateV1,
    ecx_execution_v1::EcxTradingVaultWitnessV1};

pub(crate) struct EcxOwnedVaultViewV1<'a> {
    pub state_bytes: &'a [u8],
    pub source_outpoint_bytes: &'a [u8],
    pub source_transaction_bytes: &'a [u8],
    pub successor_transaction_bytes: &'a [u8],
    pub successor_vout: u32,
    pub successor_script_sha256: Hash32,
    pub account: &'a EcxOwnedAccountV1,
    pub prior_accounts: &'a [(TraderLeafV2, Vec<u8>)],
    pub successor_accounts: &'a [(TraderLeafV2, Vec<u8>)],
}

impl EcxOwnedVaultViewV1<'_> {
    pub fn with_decoded<R>(&self, action: impl FnOnce(
        &EcxSuccessorStateV1, elements::OutPoint, EcxAccountOpeningV1<'_>,
        &EcxTradingVaultWitnessV1<'_>,
    ) -> Result<R, ProofErrorV2>) -> Result<R, ProofErrorV2> {
        let invalid = || ProofErrorV2::BindingMismatch("ECX owned vault encoding");
        let state = EcxSuccessorStateV1::decode(self.state_bytes)?;
        let source = elements::encode::deserialize(self.source_transaction_bytes).map_err(|_| invalid())?;
        let successor = elements::encode::deserialize(self.successor_transaction_bytes).map_err(|_| invalid())?;
        let outpoint = elements::encode::deserialize(self.source_outpoint_bytes).map_err(|_| invalid())?;
        let decode = |ledger: &[(TraderLeafV2, Vec<u8>)]| ledger.iter()
            .map(|(_, bytes)| EcxCashAccountV1::from_bytes(bytes)).collect::<Result<Vec<_>, _>>();
        let prior_cash = decode(self.prior_accounts)?;
        let successor_cash = decode(self.successor_accounts)?;
        let prior_accounts: Vec<_> = self.prior_accounts.iter().zip(&prior_cash)
            .map(|((position, _), cash)| (position, cash)).collect();
        let successor_accounts: Vec<_> = self.successor_accounts.iter().zip(&successor_cash)
            .map(|((position, _), cash)| (position, cash)).collect();
        let vault = EcxTradingVaultWitnessV1 {
            source_outpoint: outpoint, source_transaction: &source,
            successor_transaction: &successor, successor_vout: self.successor_vout,
            source_script_sha256: state.vault_script_sha256,
            successor_script_sha256: self.successor_script_sha256,
            prior_accounts: &prior_accounts, successor_accounts: &successor_accounts,
        };
        let cash = EcxCashAccountV1::from_bytes(&self.account.cash_bytes)?;
        action(&state, outpoint, EcxAccountOpeningV1 { position: &self.account.position,
            cash: &cash, siblings: &self.account.siblings }, &vault)
    }
}
