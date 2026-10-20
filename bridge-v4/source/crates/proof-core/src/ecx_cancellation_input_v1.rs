//! Owned signed cancellation relation. Decoding does not authenticate chain
//! inclusion or the predecessor; the native continuation must enforce both.
use bincode::Options;
use serde::{Deserialize, Serialize};
use ecx_protocol_core::{Hash32, TraderLeafV2,
    ecx_cash_account_v1::{EcxAccountOpeningV1},
    ecx_configuration_v1::{EcxConfigurationV1, EcxSuccessorBindingsV1},
    ecx_cancel_v1::SignedEcxCancelV1, ecx_order_v1::EcxAdmittedOrderV2};
use crate::{proof_v2::ProofErrorV2, ecx_match_input_v1::EcxOwnedAccountV1,
    ecx_successor_state_v1::EcxSuccessorStateV1,
    ecx_execution_v1::{EcxTradingVaultWitnessV1, verify_ecx_cancellation_v1}};

pub const MAX_ECX_CANCELLATION_INPUT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcxCancellationInputV1 {
    pub expected_state: Hash32,
    pub state_bytes: Vec<u8>,
    pub bindings: EcxSuccessorBindingsV1,
    pub economics: EcxConfigurationV1,
    pub signed: SignedEcxCancelV1,
    pub account: EcxOwnedAccountV1,
    pub order: EcxAdmittedOrderV2,
    pub order_siblings: Vec<Hash32>,
    pub source_outpoint_bytes: Vec<u8>,
    pub source_transaction_bytes: Vec<u8>,
    pub successor_transaction_bytes: Vec<u8>,
    pub successor_vout: u32,
    pub successor_script_sha256: Hash32,
    pub prior_accounts: Vec<(TraderLeafV2, Vec<u8>)>,
    pub successor_accounts: Vec<(TraderLeafV2, Vec<u8>)>,
}

impl EcxCancellationInputV1 {
    fn invalid() -> ProofErrorV2 {
        ProofErrorV2::BindingMismatch("ECX cancellation input encoding")
    }
    pub fn encode(&self) -> Result<Vec<u8>, ProofErrorV2> {
        let payload = bincode::DefaultOptions::new().with_fixint_encoding()
            .with_limit((MAX_ECX_CANCELLATION_INPUT_BYTES - 6) as u64)
            .serialize(self).map_err(|_| Self::invalid())?;
        let mut bytes = b"ECXCA2".to_vec();
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ProofErrorV2> {
        if bytes.len() > MAX_ECX_CANCELLATION_INPUT_BYTES || !bytes.starts_with(b"ECXCA2") {
            return Err(Self::invalid());
        }
        bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes()
            .with_limit((MAX_ECX_CANCELLATION_INPUT_BYTES - 6) as u64)
            .deserialize(&bytes[6..]).map_err(|_| Self::invalid())
    }
    pub fn execute(&self) -> Result<EcxSuccessorStateV1, ProofErrorV2> {
        self.with_decoded_witness(|state, outpoint, account, vault| {
            verify_ecx_cancellation_v1(self.expected_state, state, outpoint,
                self.bindings, self.economics, &self.signed, account,
                &self.order, &self.order_siblings, vault)
        })
    }
    pub fn with_decoded_witness<R>(&self, action: impl FnOnce(
        &EcxSuccessorStateV1, elements::OutPoint, EcxAccountOpeningV1<'_>,
        &EcxTradingVaultWitnessV1<'_>,
    ) -> Result<R, ProofErrorV2>) -> Result<R, ProofErrorV2> {
        crate::ecx_owned_vault_v1::EcxOwnedVaultViewV1 {
            state_bytes: &self.state_bytes, source_outpoint_bytes: &self.source_outpoint_bytes,
            source_transaction_bytes: &self.source_transaction_bytes,
            successor_transaction_bytes: &self.successor_transaction_bytes,
            successor_vout: self.successor_vout, successor_script_sha256: self.successor_script_sha256,
            account: &self.account, prior_accounts: &self.prior_accounts,
            successor_accounts: &self.successor_accounts,
        }.with_decoded(action)
    }
}
