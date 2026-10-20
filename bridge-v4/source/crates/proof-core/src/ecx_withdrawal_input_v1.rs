//! Owned withdrawal witness for host/native composition. ECXWI2 is distinct
//! from the match transport: withdrawals do not advance the matcher cursor.
//! Decoding is not authentication, inclusion, or permission to spend a vault.
use bincode::Options;
use serde::{Deserialize, Serialize};
use ecx_protocol_core::{Hash32, TraderLeafV2, FrozenConfigurationV2,
    ecx_cash_account_v1::{EcxAccountOpeningV1},
    ecx_configuration_v1::{EcxConfigurationV1, EcxSuccessorBindingsV1},
    ecx_order_v1::EcxAdmittedOrderV2,
    ecx_withdrawal_v1::SignedEcxWithdrawalV1,
    funding_v2::FundingStateV2};
use crate::{ConversionLegConsensusProofV2, proof_v2::ProofErrorV2,
    ecx_match_input_v1::{ConsensusProofVerifier, TruthcoinConsensusProofV1, EcxOwnedAccountV1},
    ecx_successor_state_v1::EcxSuccessorStateV1,
    ecx_execution_v1::{EcxTradingVaultWitnessV1, verify_ecx_oracle_withdrawal_v1}};

pub const MAX_ECX_WITHDRAWAL_INPUT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcxWithdrawalInputV1 {
    pub expected_state: Hash32,
    pub state_bytes: Vec<u8>,
    pub bindings: EcxSuccessorBindingsV1,
    pub economics: EcxConfigurationV1,
    pub configuration: FrozenConfigurationV2,
    pub truthcoin: TruthcoinConsensusProofV1,
    pub ecx_btc: ConversionLegConsensusProofV2,
    pub usdd_usd: ConversionLegConsensusProofV2,
    pub funding: FundingStateV2,
    pub signed: SignedEcxWithdrawalV1,
    pub account: EcxOwnedAccountV1,
    pub orders: Vec<EcxAdmittedOrderV2>,
    pub source_outpoint_bytes: Vec<u8>,
    pub source_transaction_bytes: Vec<u8>,
    pub successor_transaction_bytes: Vec<u8>,
    pub successor_vout: u32,
    pub recipient_vout: u32,
    pub successor_script_sha256: Hash32,
    pub prior_accounts: Vec<(TraderLeafV2, Vec<u8>)>,
    pub successor_accounts: Vec<(TraderLeafV2, Vec<u8>)>,
}

impl EcxWithdrawalInputV1 {
    pub fn encode(&self) -> Result<Vec<u8>, ProofErrorV2> {
        let payload = bincode::DefaultOptions::new().with_fixint_encoding()
            .with_limit((MAX_ECX_WITHDRAWAL_INPUT_BYTES - 6) as u64).serialize(self)
            .map_err(|_| Self::invalid())?;
        let mut bytes = b"ECXWI2".to_vec();
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProofErrorV2> {
        if bytes.len() > MAX_ECX_WITHDRAWAL_INPUT_BYTES || !bytes.starts_with(b"ECXWI2") {
            return Err(Self::invalid());
        }
        bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes()
            .with_limit((MAX_ECX_WITHDRAWAL_INPUT_BYTES - 6) as u64)
            .deserialize(&bytes[6..]).map_err(|_| Self::invalid())
    }

    fn invalid() -> ProofErrorV2 {
        ProofErrorV2::BindingMismatch("ECX withdrawal input encoding")
    }

    /// Recompute the oracle-backed relation. The enclosing native continuation
    /// must independently pin this opening, context, policy and source outpoint,
    /// authenticate both UTXO paths, and enforce outstanding-position risk.
    pub fn execute<V: ConsensusProofVerifier>(&self, verifier: &V)
        -> Result<(EcxSuccessorStateV1, FundingStateV2), ProofErrorV2>
    {
        self.with_decoded_witness(|state, outpoint, account, vault, orders| {
            verify_ecx_oracle_withdrawal_v1(self.expected_state, state, outpoint,
                self.bindings, self.economics, &self.configuration, &self.truthcoin,
                &self.ecx_btc, &self.usdd_usd, verifier, &self.funding, &self.signed,
                account, vault, self.recipient_vout, orders)
        })
    }

    /// Borrow decoded data for the native verifier without maintaining a second
    /// transaction/ledger decoder. This performs no authentication by itself.
    pub fn with_decoded_witness<R>(&self, action: impl FnOnce(
        &EcxSuccessorStateV1, elements::OutPoint, EcxAccountOpeningV1<'_>,
        &EcxTradingVaultWitnessV1<'_>, &[&EcxAdmittedOrderV2],
    ) -> Result<R, ProofErrorV2>) -> Result<R, ProofErrorV2> {
        crate::ecx_owned_vault_v1::EcxOwnedVaultViewV1 {
            state_bytes: &self.state_bytes, source_outpoint_bytes: &self.source_outpoint_bytes,
            source_transaction_bytes: &self.source_transaction_bytes,
            successor_transaction_bytes: &self.successor_transaction_bytes,
            successor_vout: self.successor_vout, successor_script_sha256: self.successor_script_sha256,
            account: &self.account, prior_accounts: &self.prior_accounts,
            successor_accounts: &self.successor_accounts,
        }.with_decoded(|state, outpoint, account, vault| {
            let orders: Vec<_> = self.orders.iter().collect();
            action(state, outpoint, account, vault, &orders)
        })
    }
}
