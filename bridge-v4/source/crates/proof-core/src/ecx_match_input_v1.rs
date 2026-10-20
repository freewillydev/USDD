//! Owned host/guest witness for the ECX ordinary-match relation. This is not
//! the legacy USDD successor witness, nor proof of predecessor inclusion.
use bincode::Options;
use serde::{Deserialize, Serialize};
use ecx_protocol_core::{Hash32, TraderLeafV2, FrozenConfigurationV2,
    ecx_cash_account_v1::{EcxCashAccountV1, EcxAccountOpeningV1},
    ecx_configuration_v1::{EcxConfigurationV1, EcxSuccessorBindingsV1},
    ecx_order_v1::EcxAdmittedOrderV2,
    ecx_order_index_v1::{EcxIndexedOrderOpeningV1, EcxMatchFeeWitnessV1},
    ecx_matcher_v1::EcxMatcherExecutionReceiptV1,
    funding_v2::FundingStateV2,
    successor_matcher_v2::SuccessorCentralMatcherConfigV2};
pub use ecx_truthcoin_proof::{ConsensusProofVerifier, ConsensusProofVerificationError,
    TruthcoinConsensusProofV1};
use crate::{ConversionLegConsensusProofV2, proof_v2::ProofErrorV2,
    ecx_successor_state_v1::EcxSuccessorStateV1,
    ecx_execution_v1::{EcxTradingVaultWitnessV1, EcxOracleMatchResultV1,
        verify_ecx_committed_match_v1}};

pub const MAX_ECX_MATCH_INPUT_BYTES: usize = 64 * 1024 * 1024;

/// Decoded data is not an authenticated receipt. Consumers must call
/// `verify_receipt` with independently authenticated predecessor pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcxMatchJournalV1 {
    pub predecessor: Hash32,
    pub source_outpoint: elements::OutPoint,
    pub next_state: EcxSuccessorStateV1,
}

impl EcxMatchJournalV1 {
    pub const LENGTH: usize = 384;

    pub fn decode(bytes: &[u8]) -> Result<Self, ProofErrorV2> {
        let invalid = || ProofErrorV2::BindingMismatch("ECX match journal encoding");
        if bytes.len() != Self::LENGTH || &bytes[..6] != b"ECXMJ1" {
            return Err(invalid());
        }
        let predecessor = bytes[6..38].try_into().map_err(|_| invalid())?;
        let source_outpoint: elements::OutPoint = elements::encode::deserialize(&bytes[38..74])
            .map_err(|_| invalid())?;
        if predecessor == [0; 32] || source_outpoint.is_null() { return Err(invalid()); }
        Ok(Self { predecessor, source_outpoint,
            next_state: EcxSuccessorStateV1::decode(&bytes[74..])? })
    }

    /// Authenticate the role-specific child receipt and its pinned local
    /// predecessor. This does not establish coin inclusion, block advancement,
    /// finality, or native covenant acceptance; those remain outer obligations.
    pub fn verify_receipt<V: ConsensusProofVerifier>(
        bytes: &[u8], proof: &[u8], verifier: &V,
        expected_predecessor: Hash32, prior: &EcxSuccessorStateV1,
        expected_outpoint: elements::OutPoint, bindings: EcxSuccessorBindingsV1,
    ) -> Result<Self, ProofErrorV2> {
        let invalid = || ProofErrorV2::BindingMismatch("ECX match receipt binding");
        let journal = Self::decode(bytes)?;
        let binding_hash = bindings.digest().map_err(|_| invalid())?;
        if prior.digest()? != expected_predecessor
            || journal.predecessor != expected_predecessor
            || journal.source_outpoint != expected_outpoint
            || prior.bindings_hash != binding_hash
            || journal.next_state.bindings_hash != binding_hash
            // Ordinary matching does not advance authenticated chain context.
            || journal.next_state.sidechain_height != prior.sidechain_height
            || journal.next_state.parent_hash != prior.parent_hash
            || journal.next_state.parent_height != prior.parent_height
            || journal.next_state.parent_mtp != prior.parent_mtp
            || journal.next_state.controlled_ecx_atoms != prior.controlled_ecx_atoms
        { return Err(invalid()); }
        verifier.verify(bindings.account_execution_program_id, bytes, proof)
            .map_err(|_| ProofErrorV2::BindingMismatch("ECX match receipt verification"))?;
        Ok(journal)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EcxOwnedAccountV1 {
    pub position: TraderLeafV2,
    /// Canonical cash codec preserves its private representation invariants.
    pub cash_bytes: Vec<u8>,
    pub siblings: Vec<Hash32>,
}
impl EcxOwnedAccountV1 {
    fn opening<'a>(&'a self, cash: &'a EcxCashAccountV1) -> EcxAccountOpeningV1<'a> {
        EcxAccountOpeningV1 { position: &self.position, cash, siblings: &self.siblings }
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct EcxOwnedOrderV1 {
    pub order: EcxAdmittedOrderV2,
    pub account: EcxOwnedAccountV1,
    pub siblings: Vec<Hash32>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct EcxOwnedFeesV1 {
    pub insurance: EcxOwnedAccountV1,
    pub maker_siblings: Vec<Hash32>,
    pub taker_siblings: Vec<Hash32>,
    pub final_insurance_siblings: Vec<Hash32>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct EcxMatchInputV1 {
    /// Complete source book authenticated against the predecessor's order root.
    /// ECXMI3 carries sequence-bound V2 records; older formats reject.
    pub source_orders: Vec<ecx_protocol_core::ecx_order_v1::EcxAdmittedOrderV2>,
    pub expected_state: Hash32,
    pub state_bytes: Vec<u8>,
    pub bindings: EcxSuccessorBindingsV1,
    pub economics: EcxConfigurationV1,
    pub configuration: FrozenConfigurationV2,
    pub truthcoin: TruthcoinConsensusProofV1,
    pub ecx_btc: ConversionLegConsensusProofV2,
    pub usdd_usd: ConversionLegConsensusProofV2,
    pub funding: FundingStateV2,
    pub matcher: SuccessorCentralMatcherConfigV2,
    pub receipt: EcxMatcherExecutionReceiptV1,
    pub maker: EcxOwnedOrderV1,
    pub taker: EcxOwnedOrderV1,
    pub clearing: EcxOwnedAccountV1,
    pub fees: Option<EcxOwnedFeesV1>,
    pub quantity: u64,
    pub source_outpoint_bytes: Vec<u8>,
    pub source_transaction_bytes: Vec<u8>,
    pub successor_transaction_bytes: Vec<u8>,
    pub successor_vout: u32,
    pub successor_script_sha256: Hash32,
    pub prior_accounts: Vec<(TraderLeafV2, Vec<u8>)>,
    pub successor_accounts: Vec<(TraderLeafV2, Vec<u8>)>,
}
impl EcxMatchInputV1 {
    /// Exact child journal: role/version, pinned predecessor, consensus
    /// outpoint and checked next state. Execution cannot be bypassed by
    /// supplying an independently assembled result.
    pub fn execute_journal<V: ConsensusProofVerifier>(&self, verifier: &V) -> Result<Vec<u8>, ProofErrorV2> {
        let result = self.execute(verifier)?;
        let outpoint: elements::OutPoint = elements::encode::deserialize(&self.source_outpoint_bytes)
            .map_err(|_| ProofErrorV2::BindingMismatch("ECX match journal outpoint"))?;
        let mut bytes = b"ECXMJ1".to_vec();
        bytes.extend_from_slice(&self.expected_state);
        bytes.extend_from_slice(&elements::encode::serialize(&outpoint));
        bytes.extend_from_slice(&result.next_state.encode()?);
        Ok(bytes)
    }
    pub fn encode(&self) -> Result<Vec<u8>, ProofErrorV2> {
        let payload = bincode::DefaultOptions::new().with_fixint_encoding()
            .with_limit((MAX_ECX_MATCH_INPUT_BYTES - 6) as u64).serialize(self)
            .map_err(|_| ProofErrorV2::BindingMismatch("ECX match input encoding"))?;
        let mut bytes = b"ECXMI3".to_vec();
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ProofErrorV2> {
        let invalid = || ProofErrorV2::BindingMismatch("ECX match input encoding");
        if bytes.len() > MAX_ECX_MATCH_INPUT_BYTES || !bytes.starts_with(b"ECXMI3") {
            return Err(invalid());
        }
        bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes()
            .with_limit((MAX_ECX_MATCH_INPUT_BYTES - 6) as u64)
            .deserialize(&bytes[6..]).map_err(|_| invalid())
    }
    pub fn execute<V: ConsensusProofVerifier>(&self, verifier: &V)
        -> Result<EcxOracleMatchResultV1, ProofErrorV2>
    {
        let state = EcxSuccessorStateV1::decode(&self.state_bytes)?;
        let invalid = || ProofErrorV2::BindingMismatch("ECX match transaction encoding");
        let source = elements::encode::deserialize(&self.source_transaction_bytes).map_err(|_| invalid())?;
        let successor = elements::encode::deserialize(&self.successor_transaction_bytes).map_err(|_| invalid())?;
        let outpoint = elements::encode::deserialize(&self.source_outpoint_bytes).map_err(|_| invalid())?;
        let decode_ledger = |ledger: &[(TraderLeafV2, Vec<u8>)]| {
            ledger.iter().map(|(_, bytes)| EcxCashAccountV1::from_bytes(bytes))
                .collect::<Result<Vec<_>, _>>()
        };
        let prior_cash = decode_ledger(&self.prior_accounts)?;
        let successor_cash = decode_ledger(&self.successor_accounts)?;
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
        let maker_cash = EcxCashAccountV1::from_bytes(&self.maker.account.cash_bytes)?;
        let taker_cash = EcxCashAccountV1::from_bytes(&self.taker.account.cash_bytes)?;
        let clearing_cash = EcxCashAccountV1::from_bytes(&self.clearing.cash_bytes)?;
        let insurance_cash = self.fees.as_ref().map(|f|
            EcxCashAccountV1::from_bytes(&f.insurance.cash_bytes)).transpose()?;
        let fees = self.fees.as_ref().zip(insurance_cash.as_ref()).map(|(f, cash)|
            EcxMatchFeeWitnessV1 { insurance: f.insurance.opening(cash),
                maker_siblings: &f.maker_siblings, taker_siblings: &f.taker_siblings,
                final_insurance_siblings: &f.final_insurance_siblings });
        verify_ecx_committed_match_v1(self.expected_state, &state, &vault,
            self.bindings, self.economics, &self.configuration, &self.truthcoin,
            &self.ecx_btc, &self.usdd_usd, verifier, &self.funding, &self.matcher,
            &self.receipt,
            EcxIndexedOrderOpeningV1 { order: &self.maker.order,
                account: self.maker.account.opening(&maker_cash), order_siblings: &self.maker.siblings },
            EcxIndexedOrderOpeningV1 { order: &self.taker.order,
                account: self.taker.account.opening(&taker_cash), order_siblings: &self.taker.siblings },
            self.clearing.opening(&clearing_cash), self.quantity, fees,
            &self.source_orders.iter().collect::<Vec<_>>())
    }
}
