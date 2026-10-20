//! Canonical wire input and concrete recursive composition for one
//! conversion-grade full-Elements transition.

use crate::bmm_v2::BmmL1StateV2;
use crate::elements_v2::{
    DrivechainDepositReceiptVerifierV2, ElementsEconomicLeafV2, ElementsSimplicityReceiptBindingV2,
    ElementsSimplicityReceiptVerifierV2, ElementsSparseEconomicMutationV2,
    ElementsSparseEconomicNodeV2, ElementsSparseUtxoMutationV2, ElementsSparseUtxoNodeV2,
    ElementsStateErrorV2, ElementsTransactionEconomicWitnessV2, ElementsTransactionKernelWitnessV2,
    ElementsTransactionUtxoWitnessV2, ElementsUtxoLeafV2, FullBitcoinDrivechainDepositEvidenceV2,
    FullBitcoinDrivechainDepositVerifierV2, FullElementsInputVerifierV2,
    FullElementsInputVerifierWithSimplicityV2, ProofCarryingElementsSimplicityExecutorV2,
};
use crate::elements_wire_v2::decode_elements_output_with_witness_v2;
use crate::full_elements_v2::{
    decode_elements_consensus_configuration_v2,
    full_elements_conversion_transition_public_values_v2,
    verify_full_patched_elements_conversion_block_v2, ElementsHeaderStateV2,
    ElementsRedemptionCapabilityReceiptBindingV2, ElementsRedemptionCapabilityReceiptVerifierV2,
    FiniteV18CovenantStateV2, FiniteV18ExchangeProofContextV2,
    FiniteV18Groth16ExchangeStateVerifierV2, FullElementsConversionTransitionPublicValuesV2,
    FullPatchedElementsBlockAuthorizationVerifierV2,
    PatchedElementsEconomicBlockExecutionWitnessV2, PatchedElementsHeaderContextV2,
    ProofCarryingElementsRedemptionCapabilityVerifierV2,
};
use bincode::Options;
use ecx_sp1_consensus_interface::{Groth16Sp1Backend, ProgramId};
use elements::hashes::Hash as _;
use elements::{BlockHash, OutPoint};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Input wire revision 4 preserves mandatory output witnesses and encodes
/// outpoints as exact 36-byte native consensus values. Inputs 1/2/3 must be
/// regenerated, not relabeled. The public journal remains revision 3; changed
/// guests nevertheless require newly derived and qualified program identities.
pub const FULL_ELEMENTS_TRANSITION_INPUT_WIRE_VERSION_V4: u8 = 4;
pub const FULL_ELEMENTS_TRANSITION_INPUT_VERSION_V2: u8 =
    FULL_ELEMENTS_TRANSITION_INPUT_WIRE_VERSION_V4;
pub const MAX_FULL_ELEMENTS_TRANSITION_INPUT_BYTES_V2: usize = 512 * 1024 * 1024;
pub const MAX_FULL_ELEMENTS_DEPOSIT_EVIDENCE_V2: usize = 4_096;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchedElementsHeaderContextWireV2 {
    pub previous_header_state: ElementsHeaderStateV2,
    pub previous_block_hash: [u8; 32],
    pub next_height: u32,
    pub previous_11_times: Vec<u32>,
    pub authenticated_adjusted_time: u64,
    pub expected_current_dynafed_parameters: Vec<u8>,
    pub expected_full_current_dynafed_parameters: Vec<u8>,
    pub expected_forced_inbox_root: [u8; 32],
    pub expected_deposit_inbox_root: [u8; 32],
    pub expected_parent_height: u32,
    pub expected_forced_processed_cursor: u64,
    pub expected_deposit_processed_cursor: u64,
    pub expected_source_backlog_oldest_parent_height: u64,
}

impl PatchedElementsHeaderContextWireV2 {
    fn decode(&self) -> Result<PatchedElementsHeaderContextV2, FullElementsTransitionInputErrorV2> {
        let current = decode_params(&self.expected_current_dynafed_parameters)?;
        let full = decode_params(&self.expected_full_current_dynafed_parameters)?;
        Ok(PatchedElementsHeaderContextV2 {
            previous_header_state: self.previous_header_state.clone(),
            previous_block_hash: self.previous_block_hash,
            next_height: self.next_height,
            previous_11_times: self.previous_11_times.clone(),
            authenticated_adjusted_time: self.authenticated_adjusted_time,
            expected_current_dynafed_parameters: current,
            expected_full_current_dynafed_parameters: full,
            expected_forced_inbox_root: self.expected_forced_inbox_root,
            expected_deposit_inbox_root: self.expected_deposit_inbox_root,
            expected_parent_height: self.expected_parent_height,
            expected_forced_processed_cursor: self.expected_forced_processed_cursor,
            expected_deposit_processed_cursor: self.expected_deposit_processed_cursor,
            expected_source_backlog_oldest_parent_height: self
                .expected_source_backlog_oldest_parent_height,
        })
    }
}

fn decode_params(
    bytes: &[u8],
) -> Result<elements::dynafed::Params, FullElementsTransitionInputErrorV2> {
    let value = elements::encode::deserialize(bytes)
        .map_err(|_| FullElementsTransitionInputErrorV2::NonCanonicalInput)?;
    if elements::encode::serialize(&value) != bytes {
        return Err(FullElementsTransitionInputErrorV2::NonCanonicalInput);
    }
    Ok(value)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsUtxoLeafWireV2 {
    #[serde(with = "crate::elements_wire_v2::outpoint")]
    pub outpoint: OutPoint,
    /// Canonical consensus TxOut bytes, which omit the output witness.
    pub output: Vec<u8>,
    /// Canonical consensus TxOutWitness bytes, mandatory even when empty.
    pub output_witness: Vec<u8>,
    pub creation_height: u32,
    pub creation_parent_mtp: u32,
    pub coinbase: bool,
    pub created_by_issuance: bool,
    pub created_by_pegin: bool,
}

impl ElementsUtxoLeafWireV2 {
    /// Preserve both output components; this does not authenticate the leaf.
    pub fn from_native(leaf: &ElementsUtxoLeafV2) -> Self {
        Self {
            outpoint: leaf.outpoint,
            output: elements::encode::serialize(&leaf.output),
            output_witness: elements::encode::serialize(&leaf.output.witness),
            creation_height: leaf.creation_height,
            creation_parent_mtp: leaf.creation_parent_mtp,
            coinbase: leaf.coinbase,
            created_by_issuance: leaf.created_by_issuance,
            created_by_pegin: leaf.created_by_pegin,
        }
    }

    pub fn decode(&self) -> Result<ElementsUtxoLeafV2, FullElementsTransitionInputErrorV2> {
        let output = decode_elements_output_with_witness_v2(&self.output, &self.output_witness)
            .map_err(|_| FullElementsTransitionInputErrorV2::NonCanonicalInput)?;
        Ok(ElementsUtxoLeafV2 {
            outpoint: self.outpoint,
            output,
            creation_height: self.creation_height,
            creation_parent_mtp: self.creation_parent_mtp,
            coinbase: self.coinbase,
            created_by_issuance: self.created_by_issuance,
            created_by_pegin: self.created_by_pegin,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsUtxoMutationWireV2 {
    #[serde(with = "crate::elements_wire_v2::outpoint")]
    pub outpoint: OutPoint,
    pub old_leaf: Option<ElementsUtxoLeafWireV2>,
    pub new_leaf: Option<ElementsUtxoLeafWireV2>,
    pub path: crate::elements_v2::ElementsSparseUtxoPathV2,
}

impl ElementsUtxoMutationWireV2 {
    pub fn from_native(mutation: &ElementsSparseUtxoMutationV2) -> Self {
        Self {
            outpoint: mutation.outpoint,
            old_leaf: mutation
                .old_leaf
                .as_ref()
                .map(ElementsUtxoLeafWireV2::from_native),
            new_leaf: mutation
                .new_leaf
                .as_ref()
                .map(ElementsUtxoLeafWireV2::from_native),
            path: mutation.path.clone(),
        }
    }

    pub fn decode(
        &self,
    ) -> Result<ElementsSparseUtxoMutationV2, FullElementsTransitionInputErrorV2> {
        Ok(ElementsSparseUtxoMutationV2 {
            outpoint: self.outpoint,
            old_leaf: self
                .old_leaf
                .as_ref()
                .map(ElementsUtxoLeafWireV2::decode)
                .transpose()?,
            new_leaf: self
                .new_leaf
                .as_ref()
                .map(ElementsUtxoLeafWireV2::decode)
                .transpose()?,
            path: self.path.clone(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsEconomicLeafWireV2 {
    pub utxo: ElementsUtxoLeafWireV2,
    pub asset_id: [u8; 32],
    pub amount: u64,
    pub asset_blinding_factor: [u8; 32],
    pub value_blinding_factor: [u8; 32],
    pub role: crate::elements_v2::ElementsLiveEconomicRoleV2,
}

impl ElementsEconomicLeafWireV2 {
    pub fn from_native(leaf: &ElementsEconomicLeafV2) -> Self {
        Self {
            utxo: ElementsUtxoLeafWireV2::from_native(&leaf.utxo),
            asset_id: leaf.asset_id,
            amount: leaf.amount,
            asset_blinding_factor: leaf.asset_blinding_factor,
            value_blinding_factor: leaf.value_blinding_factor,
            role: leaf.role,
        }
    }

    pub fn decode(&self) -> Result<ElementsEconomicLeafV2, FullElementsTransitionInputErrorV2> {
        Ok(ElementsEconomicLeafV2 {
            utxo: self.utxo.decode()?,
            asset_id: self.asset_id,
            amount: self.amount,
            asset_blinding_factor: self.asset_blinding_factor,
            value_blinding_factor: self.value_blinding_factor,
            role: self.role,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsEconomicMutationWireV2 {
    #[serde(with = "crate::elements_wire_v2::outpoint")]
    pub outpoint: OutPoint,
    pub old_leaf: Option<ElementsEconomicLeafWireV2>,
    pub new_leaf: Option<ElementsEconomicLeafWireV2>,
    pub path: crate::elements_v2::ElementsSparseEconomicPathV2,
}

impl ElementsEconomicMutationWireV2 {
    pub fn from_native(mutation: &ElementsSparseEconomicMutationV2) -> Self {
        Self {
            outpoint: mutation.outpoint,
            old_leaf: mutation
                .old_leaf
                .as_ref()
                .map(ElementsEconomicLeafWireV2::from_native),
            new_leaf: mutation
                .new_leaf
                .as_ref()
                .map(ElementsEconomicLeafWireV2::from_native),
            path: mutation.path.clone(),
        }
    }

    pub fn decode(
        &self,
    ) -> Result<ElementsSparseEconomicMutationV2, FullElementsTransitionInputErrorV2> {
        Ok(ElementsSparseEconomicMutationV2 {
            outpoint: self.outpoint,
            old_leaf: self
                .old_leaf
                .as_ref()
                .map(ElementsEconomicLeafWireV2::decode)
                .transpose()?,
            new_leaf: self
                .new_leaf
                .as_ref()
                .map(ElementsEconomicLeafWireV2::decode)
                .transpose()?,
            path: self.path.clone(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementsTransactionStateWitnessWireV2 {
    pub spends: Vec<ElementsUtxoMutationWireV2>,
    pub creates: Vec<ElementsUtxoMutationWireV2>,
    pub economic_spends: Vec<ElementsEconomicMutationWireV2>,
    pub economic_creates: Vec<ElementsEconomicMutationWireV2>,
    pub kernel: ElementsTransactionKernelWitnessV2,
}

impl ElementsTransactionStateWitnessWireV2 {
    /// Encode native witnesses without deriving or trusting their membership.
    pub fn from_native(
        utxo: &ElementsTransactionUtxoWitnessV2,
        economic: &ElementsTransactionEconomicWitnessV2,
        kernel: &ElementsTransactionKernelWitnessV2,
    ) -> Self {
        Self {
            spends: utxo
                .spends
                .iter()
                .map(ElementsUtxoMutationWireV2::from_native)
                .collect(),
            creates: utxo
                .creates
                .iter()
                .map(ElementsUtxoMutationWireV2::from_native)
                .collect(),
            economic_spends: economic
                .spends
                .iter()
                .map(ElementsEconomicMutationWireV2::from_native)
                .collect(),
            economic_creates: economic
                .creates
                .iter()
                .map(ElementsEconomicMutationWireV2::from_native)
                .collect(),
            kernel: kernel.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FiniteV18ExchangeProofInputV2 {
    pub program_id: [u8; 32],
    pub configuration_hash: [u8; 32],
    pub renderer: crate::full_elements_v2::FiniteV18StateRendererV2,
    pub current_state: FiniteV18CovenantStateV2,
    pub next_state: FiniteV18CovenantStateV2,
    pub child_genesis: [u8; 32],
    #[serde(with = "crate::elements_wire_v2::outpoint")]
    pub previous_state_outpoint: OutPoint,
    /// Canonical consensus TxOut bytes, which omit the output witness.
    pub previous_state_output: Vec<u8>,
    /// Mandatory even for the explicit state-authority output.
    pub previous_state_output_witness: Vec<u8>,
    pub state_authority_asset_id: [u8; 32],
    pub state_authority_value: u64,
}

impl FiniteV18ExchangeProofInputV2 {
    pub fn from_context(context: &FiniteV18ExchangeProofContextV2) -> Self {
        Self {
            program_id: *context.program_id.as_bytes(),
            configuration_hash: context.configuration_hash,
            renderer: context.renderer,
            current_state: context.current_state,
            next_state: context.next_state,
            child_genesis: context.child_genesis,
            previous_state_outpoint: context.previous_state_outpoint,
            previous_state_output: elements::encode::serialize(&context.previous_state_output),
            previous_state_output_witness: elements::encode::serialize(
                &context.previous_state_output.witness,
            ),
            state_authority_asset_id: context.state_authority_asset_id,
            state_authority_value: context.state_authority_value,
        }
    }

    pub fn decode(
        &self,
    ) -> Result<FiniteV18ExchangeProofContextV2, FullElementsTransitionInputErrorV2> {
        let output = decode_elements_output_with_witness_v2(
            &self.previous_state_output,
            &self.previous_state_output_witness,
        )
        .map_err(|_| FullElementsTransitionInputErrorV2::NonCanonicalInput)?;
        Ok(FiniteV18ExchangeProofContextV2 {
            program_id: ProgramId::from_bytes(self.program_id)
                .map_err(|_| FullElementsTransitionInputErrorV2::Configuration)?,
            configuration_hash: self.configuration_hash,
            renderer: self.renderer,
            current_state: self.current_state,
            next_state: self.next_state,
            child_genesis: self.child_genesis,
            previous_state_outpoint: self.previous_state_outpoint,
            previous_state_output: output,
            state_authority_asset_id: self.state_authority_asset_id,
            state_authority_value: self.state_authority_value,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrivechainDepositVerifierInputV2 {
    pub evidence: FullBitcoinDrivechainDepositEvidenceV2,
    pub sidechain_genesis: [u8; 32],
    pub pegged_asset: [u8; 32],
    pub sidechain_address_profile: u8,
}

struct CompositeDepositVerifierV2 {
    verifiers: Vec<FullBitcoinDrivechainDepositVerifierV2>,
}

impl DrivechainDepositReceiptVerifierV2 for CompositeDepositVerifierV2 {
    fn verify_deposit_statement(
        &self,
        statement: &crate::elements_v2::DrivechainDepositStatementV2,
    ) -> Result<(), ElementsStateErrorV2> {
        if self
            .verifiers
            .iter()
            .any(|verifier| verifier.verify_deposit_statement(statement).is_ok())
        {
            Ok(())
        } else {
            Err(ElementsStateErrorV2::DrivechainDeposit)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullElementsTransitionInputV2 {
    pub version: u8,
    pub configuration_preimage: Vec<u8>,
    pub raw_block: Vec<u8>,
    pub header_context: PatchedElementsHeaderContextWireV2,
    pub initial_utxo_root: ElementsSparseUtxoNodeV2,
    pub initial_economic_root: ElementsSparseEconomicNodeV2,
    pub previous_parent_state: BmmL1StateV2,
    pub previous_exchange_state_root: [u8; 32],
    pub transactions: Vec<ElementsTransactionStateWitnessWireV2>,
    pub simplicity_receipts: Vec<ElementsSimplicityReceiptBindingV2>,
    pub deposit_verifiers: Vec<DrivechainDepositVerifierInputV2>,
    pub exchange_proof: FiniteV18ExchangeProofInputV2,
    pub redemption_capability_receipt: ElementsRedemptionCapabilityReceiptBindingV2,
}

pub trait FullElementsTransitionDeferredVerifierV2:
    ElementsSimplicityReceiptVerifierV2 + ElementsRedemptionCapabilityReceiptVerifierV2
{
}

impl<T> FullElementsTransitionDeferredVerifierV2 for T where
    T: ElementsSimplicityReceiptVerifierV2 + ElementsRedemptionCapabilityReceiptVerifierV2
{
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum FullElementsTransitionInputErrorV2 {
    #[error("full Elements transition input is noncanonical or oversized")]
    NonCanonicalInput,
    #[error("full Elements transition configuration does not match its witnesses")]
    Configuration,
    #[error("full Elements transition relation rejected")]
    Transition,
}

pub fn encode_full_elements_transition_input_v2(
    input: &FullElementsTransitionInputV2,
) -> Result<Vec<u8>, FullElementsTransitionInputErrorV2> {
    validate_shape(input)?;
    transition_options()
        .serialize(input)
        .map_err(|_| FullElementsTransitionInputErrorV2::NonCanonicalInput)
}

pub fn decode_full_elements_transition_input_v2(
    bytes: &[u8],
) -> Result<FullElementsTransitionInputV2, FullElementsTransitionInputErrorV2> {
    if bytes.first() != Some(&FULL_ELEMENTS_TRANSITION_INPUT_VERSION_V2)
        || bytes.len() > MAX_FULL_ELEMENTS_TRANSITION_INPUT_BYTES_V2
    {
        return Err(FullElementsTransitionInputErrorV2::NonCanonicalInput);
    }
    let input: FullElementsTransitionInputV2 = transition_options()
        .deserialize(bytes)
        .map_err(|_| FullElementsTransitionInputErrorV2::NonCanonicalInput)?;
    validate_shape(&input)?;
    if encode_full_elements_transition_input_v2(&input)? != bytes {
        return Err(FullElementsTransitionInputErrorV2::NonCanonicalInput);
    }
    Ok(input)
}

pub fn execute_full_elements_transition_v2<
    B: Groth16Sp1Backend,
    V: FullElementsTransitionDeferredVerifierV2,
>(
    input: &FullElementsTransitionInputV2,
    groth16_backend: &B,
    deferred_verifier: &V,
) -> Result<FullElementsConversionTransitionPublicValuesV2, FullElementsTransitionInputErrorV2> {
    validate_shape(input)?;
    let configuration = decode_elements_consensus_configuration_v2(&input.configuration_preimage)
        .map_err(|_| FullElementsTransitionInputErrorV2::Configuration)?;
    let configuration_commitment = configuration
        .commitment()
        .map_err(|_| FullElementsTransitionInputErrorV2::Configuration)?;
    let header_context = input.header_context.decode()?;
    let exchange_context = input.exchange_proof.decode()?;
    if header_context.previous_header_state.dynamic_epoch_length
        != configuration.dynamic_epoch_length
        || input.exchange_proof.program_id != configuration.finite_transition_program_id
        || input.exchange_proof.configuration_hash != configuration.finite_configuration_hash
        || input.exchange_proof.renderer != configuration.renderer
        || input.exchange_proof.child_genesis != configuration.child_genesis
        || input.exchange_proof.state_authority_asset_id != configuration.state_authority_asset_id
        || input.exchange_proof.state_authority_value != configuration.state_authority_value
    {
        return Err(FullElementsTransitionInputErrorV2::Configuration);
    }

    let mut utxos = Vec::with_capacity(input.transactions.len());
    let mut economics = Vec::with_capacity(input.transactions.len());
    let mut kernels = Vec::with_capacity(input.transactions.len());
    for transaction in &input.transactions {
        utxos.push(ElementsTransactionUtxoWitnessV2 {
            spends: transaction
                .spends
                .iter()
                .map(ElementsUtxoMutationWireV2::decode)
                .collect::<Result<_, _>>()?,
            creates: transaction
                .creates
                .iter()
                .map(ElementsUtxoMutationWireV2::decode)
                .collect::<Result<_, _>>()?,
        });
        economics.push(ElementsTransactionEconomicWitnessV2 {
            spends: transaction
                .economic_spends
                .iter()
                .map(ElementsEconomicMutationWireV2::decode)
                .collect::<Result<_, _>>()?,
            creates: transaction
                .economic_creates
                .iter()
                .map(ElementsEconomicMutationWireV2::decode)
                .collect::<Result<_, _>>()?,
        });
        kernels.push(transaction.kernel.clone());
    }
    let execution = PatchedElementsEconomicBlockExecutionWitnessV2 {
        consensus: crate::full_elements_v2::PatchedElementsBlockExecutionWitnessV2 {
            transaction_utxos: utxos,
            transaction_kernels: kernels,
        },
        transaction_economics: economics,
    };
    let simplicity = ProofCarryingElementsSimplicityExecutorV2::new(
        configuration.simplicity_evaluator_program_id,
        &input.simplicity_receipts,
        deferred_verifier,
    )
    .map_err(|_| FullElementsTransitionInputErrorV2::Transition)?;
    let input_verifier = FullElementsInputVerifierWithSimplicityV2 {
        base: FullElementsInputVerifierV2::new(BlockHash::from_byte_array(
            configuration.child_genesis,
        )),
        simplicity: &simplicity,
    };
    let deposit_verifier = CompositeDepositVerifierV2 {
        verifiers: input
            .deposit_verifiers
            .iter()
            .map(|value| FullBitcoinDrivechainDepositVerifierV2 {
                evidence: value.evidence.clone(),
                sidechain_genesis: value.sidechain_genesis,
                pegged_asset: value.pegged_asset,
                sidechain_address_profile: value.sidechain_address_profile,
            })
            .collect(),
    };
    let exchange = FiniteV18Groth16ExchangeStateVerifierV2 {
        backend: groth16_backend,
        context: exchange_context,
    };
    let capability = ProofCarryingElementsRedemptionCapabilityVerifierV2 {
        program_id: configuration.redemption_capability_program_id,
        covenant_commitment: configuration.covenant_commitment,
        receipt: &input.redemption_capability_receipt,
        verifier: deferred_verifier,
    };
    let statement = verify_full_patched_elements_conversion_block_v2(
        &input.raw_block,
        configuration_commitment,
        &header_context,
        input.initial_utxo_root,
        input.initial_economic_root,
        configuration.classification,
        &input.previous_parent_state,
        input.previous_exchange_state_root,
        &execution,
        &input_verifier,
        Some(&deposit_verifier),
        &FullPatchedElementsBlockAuthorizationVerifierV2,
        &exchange,
        &capability,
        &configuration.bmm_consensus,
    )
    .map_err(|_| FullElementsTransitionInputErrorV2::Transition)?;
    simplicity
        .require_all_receipts_consumed()
        .map_err(|_| FullElementsTransitionInputErrorV2::Transition)?;
    full_elements_conversion_transition_public_values_v2(&statement)
        .map_err(|_| FullElementsTransitionInputErrorV2::Transition)
}

fn validate_shape(
    input: &FullElementsTransitionInputV2,
) -> Result<(), FullElementsTransitionInputErrorV2> {
    if input.version != FULL_ELEMENTS_TRANSITION_INPUT_VERSION_V2
        || input.configuration_preimage.is_empty()
        || input.raw_block.is_empty()
        || input.transactions.is_empty()
        || input.deposit_verifiers.len() > MAX_FULL_ELEMENTS_DEPOSIT_EVIDENCE_V2
        || input.redemption_capability_receipt.public_values.is_empty()
        || input.redemption_capability_receipt.proof_marker.is_empty()
        || transition_options()
            .serialized_size(input)
            .map_err(|_| FullElementsTransitionInputErrorV2::NonCanonicalInput)?
            > MAX_FULL_ELEMENTS_TRANSITION_INPUT_BYTES_V2 as u64
    {
        return Err(FullElementsTransitionInputErrorV2::NonCanonicalInput);
    }
    for transaction in &input.transactions {
        for mutation in transaction.spends.iter().chain(&transaction.creates) {
            for leaf in mutation.old_leaf.iter().chain(&mutation.new_leaf) {
                leaf.decode()?;
            }
        }
        for mutation in transaction
            .economic_spends
            .iter()
            .chain(&transaction.economic_creates)
        {
            for leaf in mutation.old_leaf.iter().chain(&mutation.new_leaf) {
                leaf.decode()?;
            }
        }
    }
    decode_elements_output_with_witness_v2(
        &input.exchange_proof.previous_state_output,
        &input.exchange_proof.previous_state_output_witness,
    )
    .map_err(|_| FullElementsTransitionInputErrorV2::NonCanonicalInput)?;
    Ok(())
}

fn transition_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_big_endian()
        .with_limit(MAX_FULL_ELEMENTS_TRANSITION_INPUT_BYTES_V2 as u64)
        .reject_trailing_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elements_v2::{
        verify_elements_economic_leaf_v2, ElementsEconomicClassificationV2,
        ElementsLiveEconomicRoleV2, ElementsSparseEconomicPathV2, ElementsSparseUtxoPathV2,
    };
    use crate::full_elements_v2::FiniteV18StateRendererV2;
    use elements::confidential::{Asset, Nonce, Value};
    use elements::{AssetId, Script, TxOut, TxOutWitness};

    fn input() -> FullElementsTransitionInputV2 {
        let asset = AssetId::from_slice(&[7; 32]).unwrap();
        let output = TxOut {
            asset: Asset::Explicit(asset),
            value: Value::Explicit(1),
            nonce: Nonce::Null,
            script_pubkey: Script::from(vec![0x51]),
            witness: Default::default(),
        };
        let state = FiniteV18CovenantStateV2 {
            version: 4,
            sequence: 1,
            private_state_root: [1; 32],
            encrypted_availability_root: [2; 32],
            forced_inbox_root: [3; 32],
            deposit_inbox_root: [4; 32],
            configuration_hash: [5; 32],
            bond_state_root: [6; 32],
            funding_state_root: [7; 32],
            active_order_risk_root: [8; 32],
            position_risk_root: [9; 32],
            bond_inbox_head_root: [10; 32],
            bond_inbox_entry_count: 0,
            bond_inbox_processed_root: [11; 32],
            bond_inbox_processed_cursor: 0,
            bond_inbox_outcome_root: [12; 32],
            bond_inbox_outcome_count: 0,
            matcher_execution_sequence: 1,
            last_transition_sidechain_height: 1,
        };
        let input = FullElementsTransitionInputV2 {
            version: FULL_ELEMENTS_TRANSITION_INPUT_VERSION_V2,
            configuration_preimage: vec![1],
            raw_block: vec![1],
            header_context: PatchedElementsHeaderContextWireV2 {
                previous_header_state: ElementsHeaderStateV2 {
                    block_hash: [1; 32],
                    height: 11,
                    previous_11_times: vec![1; 11],
                    full_current_dynafed_parameters: elements::dynafed::Params::Full(
                        elements::dynafed::FullParams::new(
                            elements::Script::from(vec![0x51]),
                            1000,
                            bitcoin::ScriptBuf::new(),
                            vec![],
                            vec![],
                        ),
                    ),
                    dynamic_epoch_length: 10,
                    epoch_proposals: vec![elements::dynafed::Params::Null; 2],
                    authenticated_adjusted_time: 2,
                },
                previous_block_hash: [1; 32],
                next_height: 2,
                previous_11_times: vec![1; 11],
                authenticated_adjusted_time: 2,
                expected_current_dynafed_parameters: elements::encode::serialize(
                    &elements::dynafed::Params::Null,
                ),
                expected_full_current_dynafed_parameters: elements::encode::serialize(
                    &elements::dynafed::Params::Null,
                ),
                expected_forced_inbox_root: [2; 32],
                expected_deposit_inbox_root: [3; 32],
                expected_parent_height: 2,
                expected_forced_processed_cursor: 0,
                expected_deposit_processed_cursor: 0,
                expected_source_backlog_oldest_parent_height: 1,
            },
            initial_utxo_root: ElementsSparseUtxoNodeV2 {
                hash: [4; 32],
                aggregate: crate::elements_v2::ElementsUtxoAggregateV2 { count: 1 },
            },
            initial_economic_root: ElementsSparseEconomicNodeV2 {
                hash: [5; 32],
                aggregate: crate::elements_v2::ElementsEconomicAggregateV2 {
                    count: 1,
                    outstanding_base_atoms: 1,
                    redeemable_reserve_quote_atoms: 1,
                },
            },
            previous_parent_state: BmmL1StateV2 {
                block_hash: bitcoin::BlockHash::from_byte_array([6; 32]),
                height: 1,
                block_time: 1,
                bits: 1,
                period_start_height: 0,
                period_start_time: 1,
                recent_times: vec![1; 11],
            },
            previous_exchange_state_root: [7; 32],
            transactions: vec![ElementsTransactionStateWitnessWireV2 {
                spends: vec![],
                creates: vec![],
                economic_spends: vec![],
                economic_creates: vec![],
                kernel: ElementsTransactionKernelWitnessV2::Coinbase,
            }],
            simplicity_receipts: vec![],
            deposit_verifiers: vec![],
            exchange_proof: FiniteV18ExchangeProofInputV2 {
                program_id: [1; 32],
                configuration_hash: [5; 32],
                renderer: FiniteV18StateRendererV2 {
                    public_state_domain_sha256: [13; 32],
                    state_node_domain_sha256: [14; 32],
                    transition_cmr: [15; 32],
                    incremental_activation_cmr: [16; 32],
                    keyless_internal_key: crate::full_elements_v2::FINITE_V18_NUMS_INTERNAL_KEY,
                    simplicity_leaf_version: 0xbe,
                },
                current_state: state,
                next_state: FiniteV18CovenantStateV2 {
                    sequence: 2,
                    ..state
                },
                child_genesis: [17; 32],
                previous_state_outpoint: OutPoint::default(),
                previous_state_output: elements::encode::serialize(&output),
                previous_state_output_witness: elements::encode::serialize(&output.witness),
                state_authority_asset_id: [18; 32],
                state_authority_value: 1,
            },
            redemption_capability_receipt: ElementsRedemptionCapabilityReceiptBindingV2 {
                public_values: vec![1],
                proof_marker: vec![1],
            },
        };
        input
    }

    #[test]
    fn transition_wire_round_trips_consensus_txout_and_rejects_trailing_bytes() {
        let input = input();
        let bytes = encode_full_elements_transition_input_v2(&input).unwrap();
        assert_eq!(
            decode_full_elements_transition_input_v2(&bytes).unwrap(),
            input
        );
        // A current-shaped payload cannot opt back into an old relation merely
        // by changing its version tag. Rejection must come from
        // the explicit relation version, not an unrelated decoding failure.
        for version in [0, 1, 2, 3, 5] {
            let mut legacy = bytes.clone();
            assert_eq!(legacy[0], FULL_ELEMENTS_TRANSITION_INPUT_VERSION_V2);
            legacy[0] = version;
            assert_eq!(
                decode_full_elements_transition_input_v2(&legacy),
                Err(FullElementsTransitionInputErrorV2::NonCanonicalInput)
            );
            let mut legacy_input = input.clone();
            legacy_input.version = version;
            assert_eq!(
                encode_full_elements_transition_input_v2(&legacy_input),
                Err(FullElementsTransitionInputErrorV2::NonCanonicalInput)
            );
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_full_elements_transition_input_v2(&trailing).is_err());
    }

    fn confidential_leaf() -> (ElementsEconomicLeafV2, ElementsEconomicClassificationV2) {
        use elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
        use elements::secp256k1_zkp::{PublicKey, RangeProof, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let abf = AssetBlindingFactor::from_slice(&[2; 32]).unwrap();
        let vbf = ValueBlindingFactor::from_slice(&[3; 32]).unwrap();
        let asset = Asset::new_confidential(&secp, AssetId::from_byte_array([9; 32]), abf);
        let generator = asset.commitment().unwrap();
        let value = Value::new_confidential(&secp, 100, generator, vbf);
        let secret = SecretKey::from_slice(&[4; 32]).unwrap();
        let script_pubkey = Script::from(vec![0x51]);
        let proof = RangeProof::new(
            &secp,
            1,
            value.commitment().unwrap(),
            100,
            vbf.into_inner(),
            b"transition wire regression",
            script_pubkey.as_bytes(),
            secret,
            0,
            8,
            generator,
        )
        .unwrap();
        let leaf = ElementsEconomicLeafV2 {
            utxo: ElementsUtxoLeafV2 {
                outpoint: OutPoint {
                    txid: elements::Txid::from_byte_array(std::array::from_fn(|i| i as u8)),
                    vout: 0x01020304,
                },
                output: TxOut {
                    asset,
                    value,
                    nonce: Nonce::Confidential(PublicKey::from_secret_key(&secp, &secret)),
                    script_pubkey,
                    witness: TxOutWitness {
                        surjection_proof: None,
                        rangeproof: Some(Box::new(proof)),
                    },
                },
                creation_height: 11,
                creation_parent_mtp: 22,
                coinbase: false,
                created_by_issuance: true,
                created_by_pegin: false,
            },
            asset_id: [9; 32],
            amount: 100,
            asset_blinding_factor: [2; 32],
            value_blinding_factor: [3; 32],
            role: ElementsLiveEconomicRoleV2::OutstandingBase,
        };
        let classification = ElementsEconomicClassificationV2 {
            base_asset_id: [9; 32],
            policy_asset_id: [8; 32],
            redemption_inventory_script_sha256: [7; 32],
            reserve_script_sha256: [6; 32],
        };
        (leaf, classification)
    }

    fn populated_input(leaf: &ElementsEconomicLeafV2) -> FullElementsTransitionInputV2 {
        let utxo = ElementsTransactionUtxoWitnessV2 {
            spends: vec![ElementsSparseUtxoMutationV2 {
                outpoint: leaf.utxo.outpoint,
                old_leaf: Some(leaf.utxo.clone()),
                new_leaf: None,
                path: ElementsSparseUtxoPathV2 { siblings: vec![] },
            }],
            creates: vec![ElementsSparseUtxoMutationV2 {
                outpoint: leaf.utxo.outpoint,
                old_leaf: None,
                new_leaf: Some(leaf.utxo.clone()),
                path: ElementsSparseUtxoPathV2 { siblings: vec![] },
            }],
        };
        let economic = ElementsTransactionEconomicWitnessV2 {
            spends: vec![ElementsSparseEconomicMutationV2 {
                outpoint: leaf.utxo.outpoint,
                old_leaf: Some(leaf.clone()),
                new_leaf: None,
                path: ElementsSparseEconomicPathV2 { siblings: vec![] },
            }],
            creates: vec![ElementsSparseEconomicMutationV2 {
                outpoint: leaf.utxo.outpoint,
                old_leaf: None,
                new_leaf: Some(leaf.clone()),
                path: ElementsSparseEconomicPathV2 { siblings: vec![] },
            }],
        };
        let wire = ElementsTransactionStateWitnessWireV2::from_native(
            &utxo,
            &economic,
            &ElementsTransactionKernelWitnessV2::Ordinary,
        );
        assert_eq!(wire.spends[0].decode().unwrap(), utxo.spends[0]);
        assert_eq!(wire.creates[0].decode().unwrap(), utxo.creates[0]);
        assert_eq!(
            wire.economic_spends[0].decode().unwrap(),
            economic.spends[0]
        );
        assert_eq!(
            wire.economic_creates[0].decode().unwrap(),
            economic.creates[0]
        );
        let mut input = input();
        input.transactions = vec![wire];
        input.exchange_proof.previous_state_outpoint = leaf.utxo.outpoint;
        input
    }

    #[test]
    fn populated_transition_preserves_real_rangeproof_and_native_constructors() {
        let (leaf, classification) = confidential_leaf();
        let expected = verify_elements_economic_leaf_v2(&leaf, classification).unwrap();
        let input = populated_input(&leaf);
        let bytes = encode_full_elements_transition_input_v2(&input).unwrap();
        assert_eq!(bytes[0], 4);
        let decoded = decode_full_elements_transition_input_v2(&bytes).unwrap();
        assert_eq!(decoded, input);
        let restored = decoded.transactions[0].economic_spends[0]
            .old_leaf
            .as_ref()
            .unwrap()
            .decode()
            .unwrap();
        assert_eq!(restored, leaf);
        assert_eq!(
            verify_elements_economic_leaf_v2(&restored, classification).unwrap(),
            expected
        );
        let base_only: TxOut = elements::encode::deserialize(
            &decoded.transactions[0].spends[0]
                .old_leaf
                .as_ref()
                .unwrap()
                .output,
        )
        .unwrap();
        assert!(base_only.witness.is_empty());
        let outpoint_bytes = elements::encode::serialize(&leaf.utxo.outpoint);
        for encoded in [
            transition_options()
                .serialize(&decoded.transactions[0].spends[0])
                .unwrap(),
            transition_options()
                .serialize(&decoded.transactions[0].economic_spends[0])
                .unwrap(),
            transition_options()
                .serialize(&ElementsUtxoLeafWireV2::from_native(&leaf.utxo))
                .unwrap(),
        ] {
            assert_eq!(&encoded[..36], outpoint_bytes);
        }
        let json = serde_json::to_vec(&input).unwrap();
        assert_eq!(
            serde_json::from_slice::<FullElementsTransitionInputV2>(&json).unwrap(),
            input
        );
        let context = input.exchange_proof.decode().unwrap();
        assert_eq!(
            FiniteV18ExchangeProofInputV2::from_context(&context),
            input.exchange_proof
        );
        // Codec fidelity also applies before semantic state-authority checks:
        // a nonempty witness cannot silently turn into an empty one.
        let mut with_witness = context;
        with_witness.previous_state_output = leaf.utxo.output.clone();
        assert_eq!(
            FiniteV18ExchangeProofInputV2::from_context(&with_witness)
                .decode()
                .unwrap(),
            with_witness
        );
    }

    #[test]
    fn transition_rejects_missing_malformed_and_hostile_wire_components() {
        let (leaf, _) = confidential_leaf();
        let input = populated_input(&leaf);
        let encoded = encode_full_elements_transition_input_v2(&input).unwrap();
        for end in [0, 1, 8, encoded.len() / 2, encoded.len() - 1] {
            assert!(decode_full_elements_transition_input_v2(&encoded[..end]).is_err());
        }
        let mut hostile = encoded.clone();
        hostile[1..9].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(decode_full_elements_transition_input_v2(&hostile).is_err());
        let mut json = serde_json::to_value(&input).unwrap();
        json["transactions"][0]["spends"][0]["old_leaf"]
            .as_object_mut()
            .unwrap()
            .remove("output_witness");
        assert!(serde_json::from_value::<FullElementsTransitionInputV2>(json).is_err());
        let mut json = serde_json::to_value(&input).unwrap();
        json["exchange_proof"]
            .as_object_mut()
            .unwrap()
            .remove("previous_state_output_witness");
        assert!(serde_json::from_value::<FullElementsTransitionInputV2>(json).is_err());
        for bad in [vec![], vec![0], vec![0, 0, 0], vec![0xfd, 0, 0, 0]] {
            let mut changed = input.clone();
            changed.transactions[0].spends[0]
                .old_leaf
                .as_mut()
                .unwrap()
                .output_witness = bad.clone();
            assert!(encode_full_elements_transition_input_v2(&changed).is_err());
            let raw = transition_options().serialize(&changed).unwrap();
            assert!(decode_full_elements_transition_input_v2(&raw).is_err());
            changed = input.clone();
            changed.exchange_proof.previous_state_output_witness = bad;
            assert!(encode_full_elements_transition_input_v2(&changed).is_err());
            let raw = transition_options().serialize(&changed).unwrap();
            assert!(decode_full_elements_transition_input_v2(&raw).is_err());
        }
        let mut changed = input;
        changed.transactions[0].economic_creates[0]
            .new_leaf
            .as_mut()
            .unwrap()
            .utxo
            .output
            .push(0);
        assert!(encode_full_elements_transition_input_v2(&changed).is_err());
    }

    #[test]
    fn transported_confidential_leaf_still_requires_real_crypto() {
        let (leaf, classification) = confidential_leaf();
        let wire = ElementsEconomicLeafWireV2::from_native(&leaf);
        assert!(verify_elements_economic_leaf_v2(&wire.decode().unwrap(), classification).is_ok());
        let mut stripped = wire.clone();
        stripped.utxo.output_witness = elements::encode::serialize(&TxOutWitness::default());
        assert!(
            verify_elements_economic_leaf_v2(&stripped.decode().unwrap(), classification).is_err()
        );
        let mut wrong_opening = wire.clone();
        wrong_opening.value_blinding_factor = [5; 32];
        assert!(
            verify_elements_economic_leaf_v2(&wrong_opening.decode().unwrap(), classification)
                .is_err()
        );
        let mut wrong_script = leaf;
        wrong_script.utxo.output.script_pubkey = Script::from(vec![0x52]);
        let substituted = ElementsEconomicLeafWireV2::from_native(&wrong_script);
        assert!(
            verify_elements_economic_leaf_v2(&substituted.decode().unwrap(), classification)
                .is_err()
        );
    }
}
