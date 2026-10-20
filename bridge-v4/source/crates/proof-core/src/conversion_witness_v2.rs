//! Fail-closed witness schemas for the two V2 conversion-proof producers.
//!
//! These records make the missing authenticated inputs explicit and bounded.
//! They are not proof implementations: both execution entrypoints always
//! return an unsupported-capability error after validating the envelope. This
//! prevents scaffold ELFs or host summaries from becoming marker receipts.

use crate::{ConversionLegKindV2, ConversionLegPublicValuesV2};
use ecx_protocol_core::Hash32;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CONVERSION_PRODUCER_SCAFFOLD_VERSION_V2: u8 = 1;
pub const MAX_CONVERSION_PRODUCER_INPUT_BYTES_V2: usize = 128 * 1024 * 1024;
pub const MAX_CHAIN_SEGMENT_BLOCKS_V2: usize = 8_192;
pub const MAX_PROOF_NODES_V2: usize = 128;
pub const MAX_AUTHENTICATED_RECORDS_V2: usize = 65_536;
pub const MAX_SINGLE_CHAIN_RECORD_BYTES_V2: usize = 4 * 1024 * 1024;
pub const MAX_CHECKPOINT_PREIMAGE_BYTES_V2: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitcoinAuthenticatedHistoryWitnessV2 {
    /// Canonical preimage whose commitment is frozen by the outer deployment.
    /// The commitment codec is deliberately not implemented by this scaffold.
    pub frozen_checkpoint_preimage: Vec<u8>,
    pub checkpoint_header: Vec<u8>,
    pub checkpoint_height: u64,
    pub checkpoint_chainwork_be: Hash32,
    /// Headers preceding the checkpoint/tip that are required to derive MTP
    /// and difficulty, not a prover-supplied timestamp summary.
    pub checkpoint_context_headers: Vec<Vec<u8>>,
    /// Complete serialized Bitcoin blocks along the asserted successor branch.
    pub successor_blocks: Vec<Vec<u8>>,
    /// Competing headers/blocks required to demonstrate authenticated fork
    /// choice and reorg handling rather than accepting a caller-selected tip.
    pub competing_branch_blocks: Vec<Vec<u8>>,
    pub claimed_best_tip_hash: Hash32,
    pub claimed_best_tip_height: u64,
    pub claimed_best_chainwork_be: Hash32,
    pub required_confirmation_depth: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialOpeningRecordV2 {
    pub transaction_id: Hash32,
    pub output_index: u32,
    pub asset_id: Hash32,
    pub amount: u64,
    pub asset_blinding_factor: Hash32,
    pub value_blinding_factor: Hash32,
    pub role_commitment: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElementsAuthenticatedStateWitnessV2 {
    /// Canonical complete-state checkpoint preimage. A header or arbitrary
    /// caller-provided UTXO root is not a complete checkpoint.
    pub frozen_checkpoint_preimage: Vec<u8>,
    pub checkpoint_height: u64,
    pub checkpoint_header: Vec<u8>,
    pub complete_utxo_snapshot: Vec<u8>,
    pub authenticated_blocks: Vec<Vec<u8>>,
    pub spent_output_predecessor_transactions: Vec<Vec<u8>>,
    pub confidential_openings: Vec<ConfidentialOpeningRecordV2>,
    pub simplicity_program_bytes: Vec<u8>,
    pub claimed_state_root: Hash32,
    pub claimed_utxo_root: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthereumAccountProofWitnessV2 {
    pub address: [u8; 20],
    pub account_rlp: Vec<u8>,
    pub proof_nodes: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthereumStorageProofWitnessV2 {
    pub contract_address: [u8; 20],
    pub storage_key: Hash32,
    pub value_rlp: Vec<u8>,
    pub proof_nodes: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthereumFinalizedStateWitnessV2 {
    /// Bootstrap/predecessor receipt preimage bound by the frozen Ethereum
    /// light-client configuration and source checkpoint.
    pub frozen_checkpoint_preimage: Vec<u8>,
    pub prior_controller_state: Vec<u8>,
    pub beacon_light_client_updates: Vec<Vec<u8>>,
    pub finalized_beacon_header_ssz: Vec<u8>,
    pub finalized_execution_payload_header_ssz: Vec<u8>,
    pub account_proofs: Vec<EthereumAccountProofWitnessV2>,
    pub storage_proofs: Vec<EthereumStorageProofWitnessV2>,
    pub claimed_finalized_slot: u64,
    pub claimed_execution_block_number: u64,
    pub claimed_execution_timestamp: u64,
    pub claimed_execution_state_root: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsddElementsCheckpointLaneWitnessV2 {
    pub prior_checkpoint_record: Vec<u8>,
    pub successor_checkpoint_records: Vec<Vec<u8>>,
    pub checkpoint_authority_transactions: Vec<Vec<u8>>,
    pub checkpoint_update_proofs: Vec<Vec<u8>>,
    /// Full Elements state is still required to prove USDD issuance, burns,
    /// outstanding supply, and covenant-authorized redemption.
    pub elements_state: ElementsAuthenticatedStateWitnessV2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcxBtcConversionProducerInputV2 {
    pub version: u8,
    pub public_values: ConversionLegPublicValuesV2,
    pub bitcoin: BitcoinAuthenticatedHistoryWitnessV2,
    pub elements: ElementsAuthenticatedStateWitnessV2,
    pub redemption_covenant_deployment_preimage: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsddUsdConversionProducerInputV2 {
    pub version: u8,
    pub public_values: ConversionLegPublicValuesV2,
    pub ethereum: EthereumFinalizedStateWitnessV2,
    /// Bitcoin history is required to authenticate the BIP301/BMM commitments
    /// carrying the Elements USDD checkpoint lane.
    pub bitcoin: BitcoinAuthenticatedHistoryWitnessV2,
    pub checkpoint_lane: UsddElementsCheckpointLaneWitnessV2,
    pub redemption_covenant_deployment_preimage: Vec<u8>,
    /// Exact enforceable USD redemption definition. It may not be replaced by
    /// a ticker string, assumed peg, or operator-supplied scalar.
    pub usd_redemption_definition_preimage: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ConversionProducerErrorV2 {
    #[error("unsupported conversion-producer scaffold version")]
    UnsupportedVersion,
    #[error("conversion-producer input targets the wrong leg")]
    WrongLeg,
    #[error("conversion-producer input is missing authenticated data: {0}")]
    MissingAuthenticatedData(&'static str),
    #[error("conversion-producer input exceeds a frozen resource bound")]
    ResourceLimit,
    #[error("ECX/BTC contextual Bitcoin and full Elements validity verifier is not implemented")]
    EcxBtcFullValidityVerifierUnavailable,
    #[error("USDD/USD finalized reserve/liability state verifier is not implemented")]
    UsddEthereumReserveVerifierUnavailable,
    #[error("USDD/USD Elements checkpoint-lane/full-supply verifier is not implemented")]
    UsddElementsLinkVerifierUnavailable,
    #[error("an enforceable USD redemption definition has not been frozen and proved")]
    UsdRedemptionDefinitionUnavailable,
}

impl EcxBtcConversionProducerInputV2 {
    pub fn validate_scaffold_envelope(&self) -> Result<(), ConversionProducerErrorV2> {
        if self.version != CONVERSION_PRODUCER_SCAFFOLD_VERSION_V2 {
            return Err(ConversionProducerErrorV2::UnsupportedVersion);
        }
        if self.public_values.kind != ConversionLegKindV2::EcxBtc {
            return Err(ConversionProducerErrorV2::WrongLeg);
        }
        validate_bitcoin(&self.bitcoin)?;
        validate_elements(&self.elements)?;
        bounded_required(
            &self.redemption_covenant_deployment_preimage,
            MAX_CHECKPOINT_PREIMAGE_BYTES_V2,
            "ECX redemption covenant deployment",
        )
    }
}

impl UsddUsdConversionProducerInputV2 {
    pub fn validate_scaffold_envelope(&self) -> Result<(), ConversionProducerErrorV2> {
        if self.version != CONVERSION_PRODUCER_SCAFFOLD_VERSION_V2 {
            return Err(ConversionProducerErrorV2::UnsupportedVersion);
        }
        if self.public_values.kind != ConversionLegKindV2::UsddUsd {
            return Err(ConversionProducerErrorV2::WrongLeg);
        }
        validate_ethereum(&self.ethereum)?;
        validate_bitcoin(&self.bitcoin)?;
        bounded_required(
            &self.checkpoint_lane.prior_checkpoint_record,
            MAX_SINGLE_CHAIN_RECORD_BYTES_V2,
            "prior USDD checkpoint",
        )?;
        validate_records(&self.checkpoint_lane.successor_checkpoint_records)?;
        validate_records(&self.checkpoint_lane.checkpoint_authority_transactions)?;
        validate_records(&self.checkpoint_lane.checkpoint_update_proofs)?;
        validate_elements(&self.checkpoint_lane.elements_state)?;
        bounded_required(
            &self.redemption_covenant_deployment_preimage,
            MAX_CHECKPOINT_PREIMAGE_BYTES_V2,
            "USDD redemption covenant deployment",
        )?;
        bounded_required(
            &self.usd_redemption_definition_preimage,
            MAX_CHECKPOINT_PREIMAGE_BYTES_V2,
            "USD redemption definition",
        )
    }
}

/// Deliberately non-producing until the contextual Bitcoin and complete
/// Elements state-transition verifiers named in the error are implemented.
pub fn execute_ecx_btc_conversion_producer_v2(
    input: &EcxBtcConversionProducerInputV2,
) -> Result<Vec<u8>, ConversionProducerErrorV2> {
    input.validate_scaffold_envelope()?;
    Err(ConversionProducerErrorV2::EcxBtcFullValidityVerifierUnavailable)
}

/// Deliberately non-producing until finalized Ethereum reserve/liability state
/// and the BMM-authenticated Elements checkpoint/supply path are both linked.
pub fn execute_usdd_usd_conversion_producer_v2(
    input: &UsddUsdConversionProducerInputV2,
) -> Result<Vec<u8>, ConversionProducerErrorV2> {
    input.validate_scaffold_envelope()?;
    Err(ConversionProducerErrorV2::UsddEthereumReserveVerifierUnavailable)
}

fn validate_bitcoin(
    witness: &BitcoinAuthenticatedHistoryWitnessV2,
) -> Result<(), ConversionProducerErrorV2> {
    bounded_required(
        &witness.frozen_checkpoint_preimage,
        MAX_CHECKPOINT_PREIMAGE_BYTES_V2,
        "Bitcoin checkpoint",
    )?;
    if witness.checkpoint_header.len() != 80
        || witness.checkpoint_height == 0
        || witness.checkpoint_chainwork_be == [0; 32]
        || witness.claimed_best_tip_hash == [0; 32]
        || witness.claimed_best_tip_height < witness.checkpoint_height
        || witness.claimed_best_chainwork_be == [0; 32]
        || witness.required_confirmation_depth == 0
        || witness.checkpoint_context_headers.is_empty()
        || witness.successor_blocks.is_empty()
    {
        return Err(ConversionProducerErrorV2::MissingAuthenticatedData(
            "Bitcoin checkpoint, MTP/difficulty context, successor branch, fork choice, or confirmations",
        ));
    }
    validate_records_with_limit(
        &witness.checkpoint_context_headers,
        MAX_CHAIN_SEGMENT_BLOCKS_V2,
    )?;
    if witness
        .checkpoint_context_headers
        .iter()
        .any(|header| header.len() != 80)
    {
        return Err(ConversionProducerErrorV2::MissingAuthenticatedData(
            "exact Bitcoin context header",
        ));
    }
    validate_records_with_limit(&witness.successor_blocks, MAX_CHAIN_SEGMENT_BLOCKS_V2)?;
    validate_records_with_limit(
        &witness.competing_branch_blocks,
        MAX_CHAIN_SEGMENT_BLOCKS_V2,
    )
}

fn validate_elements(
    witness: &ElementsAuthenticatedStateWitnessV2,
) -> Result<(), ConversionProducerErrorV2> {
    bounded_required(
        &witness.frozen_checkpoint_preimage,
        MAX_CHECKPOINT_PREIMAGE_BYTES_V2,
        "Elements complete-state checkpoint",
    )?;
    bounded_required(
        &witness.checkpoint_header,
        MAX_SINGLE_CHAIN_RECORD_BYTES_V2,
        "Elements checkpoint header",
    )?;
    bounded_required(
        &witness.complete_utxo_snapshot,
        MAX_CHECKPOINT_PREIMAGE_BYTES_V2,
        "Elements complete UTXO snapshot",
    )?;
    bounded_required(
        &witness.simplicity_program_bytes,
        MAX_SINGLE_CHAIN_RECORD_BYTES_V2,
        "redemption Simplicity program",
    )?;
    if witness.checkpoint_height == 0
        || witness.authenticated_blocks.is_empty()
        || witness.claimed_state_root == [0; 32]
        || witness.claimed_utxo_root == [0; 32]
    {
        return Err(ConversionProducerErrorV2::MissingAuthenticatedData(
            "Elements checkpoint, full blocks, state root, or UTXO root",
        ));
    }
    validate_records_with_limit(&witness.authenticated_blocks, MAX_CHAIN_SEGMENT_BLOCKS_V2)?;
    validate_records(&witness.spent_output_predecessor_transactions)?;
    if witness.confidential_openings.len() > MAX_AUTHENTICATED_RECORDS_V2 {
        return Err(ConversionProducerErrorV2::ResourceLimit);
    }
    Ok(())
}

fn validate_ethereum(
    witness: &EthereumFinalizedStateWitnessV2,
) -> Result<(), ConversionProducerErrorV2> {
    bounded_required(
        &witness.frozen_checkpoint_preimage,
        MAX_CHECKPOINT_PREIMAGE_BYTES_V2,
        "Ethereum checkpoint",
    )?;
    bounded_required(
        &witness.prior_controller_state,
        MAX_SINGLE_CHAIN_RECORD_BYTES_V2,
        "Ethereum prior controller state",
    )?;
    validate_records_with_limit(&witness.beacon_light_client_updates, 4_096)?;
    bounded_required(
        &witness.finalized_beacon_header_ssz,
        MAX_SINGLE_CHAIN_RECORD_BYTES_V2,
        "finalized beacon header",
    )?;
    bounded_required(
        &witness.finalized_execution_payload_header_ssz,
        MAX_SINGLE_CHAIN_RECORD_BYTES_V2,
        "finalized execution payload header",
    )?;
    if witness.claimed_finalized_slot == 0
        || witness.claimed_execution_block_number == 0
        || witness.claimed_execution_timestamp == 0
        || witness.claimed_execution_state_root == [0; 32]
        || witness.account_proofs.is_empty()
        || witness.storage_proofs.is_empty()
        || witness.account_proofs.len() > MAX_AUTHENTICATED_RECORDS_V2
        || witness.storage_proofs.len() > MAX_AUTHENTICATED_RECORDS_V2
    {
        return Err(ConversionProducerErrorV2::MissingAuthenticatedData(
            "finalized Ethereum header, reserve/liability accounts, or storage proofs",
        ));
    }
    for proof in &witness.account_proofs {
        bounded_required(
            &proof.account_rlp,
            MAX_SINGLE_CHAIN_RECORD_BYTES_V2,
            "Ethereum account value",
        )?;
        validate_proof_nodes(&proof.proof_nodes)?;
    }
    for proof in &witness.storage_proofs {
        bounded_required(
            &proof.value_rlp,
            MAX_SINGLE_CHAIN_RECORD_BYTES_V2,
            "Ethereum storage value",
        )?;
        validate_proof_nodes(&proof.proof_nodes)?;
    }
    Ok(())
}

fn validate_proof_nodes(nodes: &[Vec<u8>]) -> Result<(), ConversionProducerErrorV2> {
    if nodes.is_empty() || nodes.len() > MAX_PROOF_NODES_V2 {
        return Err(ConversionProducerErrorV2::ResourceLimit);
    }
    validate_records_with_limit(nodes, MAX_PROOF_NODES_V2)
}

fn validate_records(records: &[Vec<u8>]) -> Result<(), ConversionProducerErrorV2> {
    validate_records_with_limit(records, MAX_AUTHENTICATED_RECORDS_V2)
}

fn validate_records_with_limit(
    records: &[Vec<u8>],
    maximum_records: usize,
) -> Result<(), ConversionProducerErrorV2> {
    if records.len() > maximum_records
        || records
            .iter()
            .any(|record| record.is_empty() || record.len() > MAX_SINGLE_CHAIN_RECORD_BYTES_V2)
    {
        return Err(ConversionProducerErrorV2::ResourceLimit);
    }
    Ok(())
}

fn bounded_required(
    bytes: &[u8],
    maximum: usize,
    name: &'static str,
) -> Result<(), ConversionProducerErrorV2> {
    if bytes.is_empty() {
        return Err(ConversionProducerErrorV2::MissingAuthenticatedData(name));
    }
    if bytes.len() > maximum {
        return Err(ConversionProducerErrorV2::ResourceLimit);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_scaffold_cannot_become_a_conversion_receipt() {
        let input = EcxBtcConversionProducerInputV2 {
            version: CONVERSION_PRODUCER_SCAFFOLD_VERSION_V2,
            public_values: public_values(ConversionLegKindV2::EcxBtc),
            bitcoin: empty_bitcoin(),
            elements: empty_elements(),
            redemption_covenant_deployment_preimage: vec![],
        };
        assert!(matches!(
            execute_ecx_btc_conversion_producer_v2(&input),
            Err(ConversionProducerErrorV2::MissingAuthenticatedData(_))
        ));
    }

    #[test]
    fn even_populated_scaffold_fails_at_missing_consensus_verifier() {
        let input = EcxBtcConversionProducerInputV2 {
            version: CONVERSION_PRODUCER_SCAFFOLD_VERSION_V2,
            public_values: public_values(ConversionLegKindV2::EcxBtc),
            bitcoin: populated_bitcoin(),
            elements: populated_elements(),
            redemption_covenant_deployment_preimage: vec![1],
        };
        assert_eq!(
            execute_ecx_btc_conversion_producer_v2(&input),
            Err(ConversionProducerErrorV2::EcxBtcFullValidityVerifierUnavailable)
        );
    }

    #[test]
    fn wrong_leg_is_rejected_before_any_producer_capability() {
        let input = EcxBtcConversionProducerInputV2 {
            version: CONVERSION_PRODUCER_SCAFFOLD_VERSION_V2,
            public_values: public_values(ConversionLegKindV2::UsddUsd),
            bitcoin: populated_bitcoin(),
            elements: populated_elements(),
            redemption_covenant_deployment_preimage: vec![1],
        };
        assert_eq!(
            input.validate_scaffold_envelope(),
            Err(ConversionProducerErrorV2::WrongLeg)
        );
    }

    fn public_values(kind: ConversionLegKindV2) -> ConversionLegPublicValuesV2 {
        ConversionLegPublicValuesV2 {
            version: 2,
            kind,
            observed_parent_block_hash: [1; 32],
            observed_parent_height: 1,
            observed_parent_mtp: 1,
            source_height: 1,
            source_mtp: 1,
            valid_until_mtp: 2,
            base_asset_id: [2; 32],
            quote_unit_id: [3; 32],
            redemption_covenant_commitment: [4; 32],
            source_checkpoint_commitment: [5; 32],
            source_state_root: [6; 32],
            quote_atoms_per_whole_base: 1,
            outstanding_base_atoms: 1,
            redeemable_reserve_quote_atoms: 1,
            redemption_enabled: true,
        }
    }

    fn empty_bitcoin() -> BitcoinAuthenticatedHistoryWitnessV2 {
        BitcoinAuthenticatedHistoryWitnessV2 {
            frozen_checkpoint_preimage: vec![],
            checkpoint_header: vec![],
            checkpoint_height: 0,
            checkpoint_chainwork_be: [0; 32],
            checkpoint_context_headers: vec![],
            successor_blocks: vec![],
            competing_branch_blocks: vec![],
            claimed_best_tip_hash: [0; 32],
            claimed_best_tip_height: 0,
            claimed_best_chainwork_be: [0; 32],
            required_confirmation_depth: 0,
        }
    }

    fn populated_bitcoin() -> BitcoinAuthenticatedHistoryWitnessV2 {
        BitcoinAuthenticatedHistoryWitnessV2 {
            frozen_checkpoint_preimage: vec![1],
            checkpoint_header: vec![1; 80],
            checkpoint_height: 1,
            checkpoint_chainwork_be: [1; 32],
            checkpoint_context_headers: vec![vec![1; 80]],
            successor_blocks: vec![vec![1]],
            competing_branch_blocks: vec![],
            claimed_best_tip_hash: [1; 32],
            claimed_best_tip_height: 2,
            claimed_best_chainwork_be: [2; 32],
            required_confirmation_depth: 1,
        }
    }

    fn empty_elements() -> ElementsAuthenticatedStateWitnessV2 {
        ElementsAuthenticatedStateWitnessV2 {
            frozen_checkpoint_preimage: vec![],
            checkpoint_height: 0,
            checkpoint_header: vec![],
            complete_utxo_snapshot: vec![],
            authenticated_blocks: vec![],
            spent_output_predecessor_transactions: vec![],
            confidential_openings: vec![],
            simplicity_program_bytes: vec![],
            claimed_state_root: [0; 32],
            claimed_utxo_root: [0; 32],
        }
    }

    fn populated_elements() -> ElementsAuthenticatedStateWitnessV2 {
        ElementsAuthenticatedStateWitnessV2 {
            frozen_checkpoint_preimage: vec![1],
            checkpoint_height: 1,
            checkpoint_header: vec![1],
            complete_utxo_snapshot: vec![1],
            authenticated_blocks: vec![vec![1]],
            spent_output_predecessor_transactions: vec![],
            confidential_openings: vec![],
            simplicity_program_bytes: vec![1],
            claimed_state_root: [1; 32],
            claimed_utxo_root: [2; 32],
        }
    }
}
