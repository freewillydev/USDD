//! Owned permissionless liquidation. Decoding does not authenticate inclusion.
use bincode::Options;
use serde::{Deserialize, Serialize};
use ecx_protocol_core::{Hash32, TraderLeafV2, FrozenConfigurationV2,
    ecx_cash_account_v1::{EcxAccountOpeningV1, EcxCashAccountV1},
    ecx_configuration_v1::{EcxConfigurationV1, EcxSuccessorBindingsV1},
    ecx_order_v1::EcxAdmittedOrderV2, funding_v2::FundingStateV2};
use crate::{ConversionLegConsensusProofV2, proof_v2::ProofErrorV2,
    ecx_match_input_v1::{ConsensusProofVerifier, TruthcoinConsensusProofV1, EcxOwnedAccountV1},
    ecx_successor_state_v1::EcxSuccessorStateV1,
    ecx_execution_v1::{EcxTradingVaultWitnessV1, verify_ecx_oracle_liquidation_batch_v1}};

pub const MAX_ECX_LIQUIDATION_INPUT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcxLiquidationInputV1 {
    pub expected_state: Hash32,
    pub state_bytes: Vec<u8>,
    pub bindings: EcxSuccessorBindingsV1,
    pub economics: EcxConfigurationV1,
    pub configuration: FrozenConfigurationV2,
    pub truthcoin: TruthcoinConsensusProofV1,
    pub ecx_btc: ConversionLegConsensusProofV2,
    pub usdd_usd: ConversionLegConsensusProofV2,
    pub funding: FundingStateV2,
    pub target: EcxOwnedAccountV1,
    pub makers: Vec<EcxOwnedAccountV1>,
    pub clearing: EcxOwnedAccountV1,
    pub insurance: EcxOwnedAccountV1,
    pub orders: Vec<(EcxAdmittedOrderV2, Vec<Hash32>)>,
    pub source_orders: Vec<EcxAdmittedOrderV2>,
    pub fills: Vec<(Hash32, u64)>,
    pub source_outpoint_bytes: Vec<u8>,
    pub source_transaction_bytes: Vec<u8>,
    pub successor_transaction_bytes: Vec<u8>,
    pub successor_vout: u32,
    pub successor_script_sha256: Hash32,
    pub prior_accounts: Vec<(TraderLeafV2, Vec<u8>)>,
    pub successor_accounts: Vec<(TraderLeafV2, Vec<u8>)>,
}

impl EcxLiquidationInputV1 {
    fn invalid() -> ProofErrorV2 {
        ProofErrorV2::BindingMismatch("ECX liquidation input encoding")
    }
    pub fn encode(&self) -> Result<Vec<u8>, ProofErrorV2> {
        let payload = bincode::DefaultOptions::new().with_fixint_encoding()
            .with_limit((MAX_ECX_LIQUIDATION_INPUT_BYTES - 6) as u64).serialize(self)
            .map_err(|_| Self::invalid())?;
        let mut bytes = b"ECXLQ1".to_vec();
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ProofErrorV2> {
        if bytes.len() > MAX_ECX_LIQUIDATION_INPUT_BYTES || !bytes.starts_with(b"ECXLQ1") {
            return Err(Self::invalid());
        }
        bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes()
            .with_limit((MAX_ECX_LIQUIDATION_INPUT_BYTES - 6) as u64)
            .deserialize(&bytes[6..]).map_err(|_| Self::invalid())
    }
    pub fn execute<V: ConsensusProofVerifier>(&self, verifier: &V)
        -> Result<(EcxSuccessorStateV1, FundingStateV2), ProofErrorV2>
    {
        self.with_decoded_witness(|state, outpoint, target, makers, clearing, insurance,
            orders, source_orders, vault| {
            let (state, funding, _) = verify_ecx_oracle_liquidation_batch_v1(
                self.expected_state, state, outpoint, self.bindings, self.economics,
                &self.configuration, &self.truthcoin, &self.ecx_btc, &self.usdd_usd,
                verifier, &self.funding, target, makers, clearing, insurance, orders,
                source_orders, &self.fills, vault)?;
            Ok((state, funding))
        })
    }

    /// The enclosing native verifier must pin the prepared state, role and
    /// source outpoint and independently authenticate both vault UTXO paths.
    pub fn with_decoded_witness<R>(&self, action: impl FnOnce(
        &EcxSuccessorStateV1, elements::OutPoint, EcxAccountOpeningV1<'_>,
        &[EcxAccountOpeningV1<'_>], EcxAccountOpeningV1<'_>, EcxAccountOpeningV1<'_>,
        &[(&EcxAdmittedOrderV2, &[Hash32])], &[&EcxAdmittedOrderV2],
        &EcxTradingVaultWitnessV1<'_>,
    ) -> Result<R, ProofErrorV2>) -> Result<R, ProofErrorV2> {
        crate::ecx_owned_vault_v1::EcxOwnedVaultViewV1 {
            state_bytes: &self.state_bytes, source_outpoint_bytes: &self.source_outpoint_bytes,
            source_transaction_bytes: &self.source_transaction_bytes,
            successor_transaction_bytes: &self.successor_transaction_bytes,
            successor_vout: self.successor_vout, successor_script_sha256: self.successor_script_sha256,
            account: &self.target, prior_accounts: &self.prior_accounts,
            successor_accounts: &self.successor_accounts,
        }.with_decoded(|state, outpoint, target, vault| {
            let maker_cash = self.makers.iter().map(|a| EcxCashAccountV1::from_bytes(&a.cash_bytes))
                .collect::<Result<Vec<_>, _>>()?;
            let makers: Vec<_> = self.makers.iter().zip(&maker_cash).map(|(a,c)|
                EcxAccountOpeningV1 { position: &a.position, cash: c, siblings: &a.siblings }).collect();
            let clearing = EcxCashAccountV1::from_bytes(&self.clearing.cash_bytes)?;
            let insurance = EcxCashAccountV1::from_bytes(&self.insurance.cash_bytes)?;
            let orders: Vec<_> = self.orders.iter().map(|(o,p)| (o,p.as_slice())).collect();
            let source_orders: Vec<_> = self.source_orders.iter().collect();
            action(state, outpoint, target, &makers,
                EcxAccountOpeningV1 { position: &self.clearing.position, cash: &clearing,
                    siblings: &self.clearing.siblings },
                EcxAccountOpeningV1 { position: &self.insurance.position, cash: &insurance,
                    siblings: &self.insurance.siblings }, &orders, &source_orders, vault)
        })
    }
}
