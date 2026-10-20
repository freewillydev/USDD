//! Concrete current-redemption capability relation for the ECX/BTC leg.

#[cfg(feature = "native-alpha")]
pub mod native_alpha;
#[cfg(feature = "native-alpha")]
pub mod native_conversion_wire;
pub mod public_pool;
#[cfg(feature="native-alpha")]
mod native_pool_lineage;

use bincode::Options;
use ecx_conversion_foundation_v2::ecx_btc::{
    ecx_btc_covenant_commitment_v2, EcxBtcCovenantDeploymentV2, BASE_ASSET_ATOMS_PER_WHOLE,
};
use ecx_full_consensus_validator_v2::elements_v2::{
    elements_sparse_economic_root_from_path_v2, elements_sparse_utxo_root_from_path_v2,
    elements_utxo_leaf_node_v2, verify_elements_economic_leaf_v2,
    verify_elements_transaction_locks_v2, ElementsEconomicLeafV2, ElementsInputVerifierV2,
    ElementsLiveEconomicRoleV2, ElementsSimplicityReceiptBindingV2,
    ElementsSimplicityReceiptVerifierV2, ElementsSparseEconomicNodeV2,
    ElementsSparseEconomicPathV2, ElementsSparseUtxoMutationV2, ElementsSparseUtxoNodeV2,
    ElementsSparseUtxoPathV2, ElementsTransactionSpendContextV2, FullElementsInputVerifierV2,
    FullElementsInputVerifierWithSimplicityV2, ProofCarryingElementsSimplicityExecutorV2,
};
use ecx_full_consensus_validator_v2::full_elements_v2::{
    decode_elements_consensus_configuration_v2,
    decode_elements_redemption_capability_public_values_v2, full_elements_economic_state_root_v2,
    ElementsRedemptionCapabilityPublicValuesV2,
};
use ecx_full_consensus_validator_v2::transition_elements_v2::ElementsEconomicLeafWireV2;
use elements::hashes::Hash as _;
use elements::secp256k1_zkp::Secp256k1;
use elements::{BlockHash, OutPoint, Transaction};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Wire revision 2 carries mandatory native output witnesses and canonical
/// outpoints. Revision-1 inputs must be regenerated. Public journal bytes are
/// unchanged, but this guest requires a newly qualified program identity.
pub const REDEMPTION_CAPABILITY_INPUT_WIRE_VERSION_V2: u8 = 2;
pub const REDEMPTION_CAPABILITY_INPUT_VERSION_V2: u8 = REDEMPTION_CAPABILITY_INPUT_WIRE_VERSION_V2;
pub const MAX_REDEMPTION_CAPABILITY_INPUT_BYTES_V2: usize = 128 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedEconomicLeafV2 {
    pub leaf: ElementsEconomicLeafWireV2,
    pub utxo_path: ElementsSparseUtxoPathV2,
    pub economic_path: ElementsSparseEconomicPathV2,
}

impl AuthenticatedEconomicLeafV2 {
    /// Package evidence without asserting its authentication. The executor
    /// independently checks both membership paths and the economic opening.
    pub fn from_native(
        leaf: &ElementsEconomicLeafV2,
        utxo_path: ElementsSparseUtxoPathV2,
        economic_path: ElementsSparseEconomicPathV2,
    ) -> Self {
        Self {
            leaf: ElementsEconomicLeafWireV2::from_native(leaf),
            utxo_path,
            economic_path,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedemptionCapabilityInputV2 {
    pub version: u8,
    pub public_values: Vec<u8>,
    pub configuration_preimage: Vec<u8>,
    pub covenant_deployment: EcxBtcCovenantDeploymentV2,
    pub terminal_utxo_root: ElementsSparseUtxoNodeV2,
    pub terminal_economic_root: ElementsSparseEconomicNodeV2,
    pub inventory: AuthenticatedEconomicLeafV2,
    pub reserve: AuthenticatedEconomicLeafV2,
    /// Hypothetical holder input. Ownership authorization is intentionally
    /// existential; the covenant inputs and economics are fully proved.
    pub holder_base_input: ElementsEconomicLeafWireV2,
    /// EOF-exact canonical Elements transaction executing one redemption.
    pub probe_transaction: Vec<u8>,
    /// Openings for payment, successor inventory, and successor reserve in
    /// exact output order.
    pub probe_outputs: Vec<ElementsEconomicLeafWireV2>,
    pub simplicity_receipts: Vec<ElementsSimplicityReceiptBindingV2>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum RedemptionCapabilityErrorV2 {
    #[error("redemption capability input is noncanonical or oversized")]
    NonCanonicalInput,
    #[error("redemption capability configuration or deployment mismatch")]
    Configuration,
    #[error("redemption capability terminal state membership failed")]
    Membership,
    #[error("canonical redemption probe economics failed")]
    Economics,
    #[error("canonical redemption covenant execution failed")]
    CovenantExecution,
}

/// State-independent probe material shared by legacy and native binding layers.
/// The enclosing relation must authenticate the two leaves and every context
/// field before invoking the engine. Success proves this probe's execution, not
/// universal permissionless authorization or deployment/successor lineage.
pub struct RedemptionProbeV3<'a> {
    pub public_values: &'a [u8],
    pub simplicity_program_bytes: &'a [u8],
    pub holder_base_input: &'a ElementsEconomicLeafWireV2,
    pub probe_transaction: &'a [u8],
    pub probe_outputs: &'a [ElementsEconomicLeafWireV2],
    pub simplicity_receipts: &'a [ElementsSimplicityReceiptBindingV2],
}

pub struct RedemptionProbeContextV3 {
    pub classification: ecx_full_consensus_validator_v2::elements_v2::ElementsEconomicClassificationV2,
    pub quote_atoms_per_whole_base: u64,
    pub simplicity_evaluator_program_id: [u8; 32],
    pub child_genesis: [u8; 32],
    pub outstanding_base_atoms: u128,
    pub source_tip_height: u64,
    pub source_tip_mtp: u64,
}

pub fn encode_redemption_capability_input_v2(
    input: &RedemptionCapabilityInputV2,
) -> Result<Vec<u8>, RedemptionCapabilityErrorV2> {
    validate_shape(input)?;
    options()
        .serialize(input)
        .map_err(|_| RedemptionCapabilityErrorV2::NonCanonicalInput)
}

pub fn decode_redemption_capability_input_v2(
    bytes: &[u8],
) -> Result<RedemptionCapabilityInputV2, RedemptionCapabilityErrorV2> {
    if bytes.first() != Some(&REDEMPTION_CAPABILITY_INPUT_VERSION_V2)
        || bytes.len() > MAX_REDEMPTION_CAPABILITY_INPUT_BYTES_V2
    {
        return Err(RedemptionCapabilityErrorV2::NonCanonicalInput);
    }
    let input: RedemptionCapabilityInputV2 = options()
        .deserialize(bytes)
        .map_err(|_| RedemptionCapabilityErrorV2::NonCanonicalInput)?;
    validate_shape(&input)?;
    if encode_redemption_capability_input_v2(&input)? != bytes {
        return Err(RedemptionCapabilityErrorV2::NonCanonicalInput);
    }
    Ok(input)
}

pub fn execute_redemption_capability_v2<V: ElementsSimplicityReceiptVerifierV2>(
    input: &RedemptionCapabilityInputV2,
    receipt_verifier: &V,
) -> Result<ElementsRedemptionCapabilityPublicValuesV2, RedemptionCapabilityErrorV2> {
    validate_shape(input)?;
    let public = decode_elements_redemption_capability_public_values_v2(&input.public_values)
        .map_err(|_| RedemptionCapabilityErrorV2::NonCanonicalInput)?;
    let configuration = decode_elements_consensus_configuration_v2(&input.configuration_preimage)
        .map_err(|_| RedemptionCapabilityErrorV2::Configuration)?;
    if configuration
        .commitment()
        .map_err(|_| RedemptionCapabilityErrorV2::Configuration)?
        != public.source_configuration_commitment
        || ecx_btc_covenant_commitment_v2(&input.covenant_deployment)
            .map_err(|_| RedemptionCapabilityErrorV2::Configuration)?
            != public.covenant_commitment
        || configuration.covenant_commitment != public.covenant_commitment
        || configuration.classification.base_asset_id
            == configuration.classification.policy_asset_id
        || input.terminal_utxo_root.hash != public.utxo_root
        || input.terminal_economic_root.hash != public.economic_root
        || input.terminal_utxo_root.aggregate.count != input.terminal_economic_root.aggregate.count
        || input
            .terminal_economic_root
            .aggregate
            .outstanding_base_atoms
            != public.outstanding_base_atoms
        || input
            .terminal_economic_root
            .aggregate
            .redeemable_reserve_quote_atoms
            != public.redeemable_reserve_quote_atoms
        || full_elements_economic_state_root_v2(
            input.terminal_utxo_root,
            input.terminal_economic_root,
            public.exchange_state_root,
        )
        .map_err(|_| RedemptionCapabilityErrorV2::Configuration)?
            != public.state_root
    {
        return Err(RedemptionCapabilityErrorV2::Configuration);
    }

    let inventory = authenticate_leaf(
        &input.inventory,
        input.terminal_utxo_root,
        input.terminal_economic_root,
        configuration.classification,
    )?;
    let reserve = authenticate_leaf(
        &input.reserve,
        input.terminal_utxo_root,
        input.terminal_economic_root,
        configuration.classification,
    )?;
    if inventory.role != ElementsLiveEconomicRoleV2::RedemptionInventory
        || reserve.role != ElementsLiveEconomicRoleV2::RedeemableReserve
        || inventory.utxo.outpoint == reserve.utxo.outpoint
    {
        return Err(RedemptionCapabilityErrorV2::Membership);
    }
    execute_redemption_probe_v3(
        &RedemptionProbeV3 {
            public_values: &input.public_values,
            simplicity_program_bytes: &input.covenant_deployment.simplicity_program_bytes,
            holder_base_input: &input.holder_base_input,
            probe_transaction: &input.probe_transaction,
            probe_outputs: &input.probe_outputs,
            simplicity_receipts: &input.simplicity_receipts,
        },
        &RedemptionProbeContextV3 {
            classification: configuration.classification,
            quote_atoms_per_whole_base: configuration.quote_atoms_per_whole_base,
            simplicity_evaluator_program_id: configuration.simplicity_evaluator_program_id,
            child_genesis: configuration.child_genesis,
            outstanding_base_atoms: public.outstanding_base_atoms,
            source_tip_height: public.source_tip_height,
            source_tip_mtp: public.source_tip_mtp,
        }, inventory, reserve, receipt_verifier,
    )?;
    Ok(public)
}

/// Execute actual amount proofs, transaction locks and recursive Simplicity
/// input verification, without imposing the legacy checkpoint/state-root ABI.
/// Inventory and reserve membership must be verified by the caller against its
/// authenticated state. The engine rechecks their openings and distinct roles.
pub fn execute_redemption_probe_v3<V: ElementsSimplicityReceiptVerifierV2>(
    input: &RedemptionProbeV3<'_>,
    context: &RedemptionProbeContextV3,
    inventory: ElementsEconomicLeafV2,
    reserve: ElementsEconomicLeafV2,
    receipt_verifier: &V,
) -> Result<(), RedemptionCapabilityErrorV2> {
    execute_redemption_probe_with_policy_v3(input, context, inventory, reserve, receipt_verifier, None)
}

fn execute_redemption_probe_with_policy_v3<V: ElementsSimplicityReceiptVerifierV2>(
    input: &RedemptionProbeV3<'_>,
    context: &RedemptionProbeContextV3,
    inventory: ElementsEconomicLeafV2,
    reserve: ElementsEconomicLeafV2,
    receipt_verifier: &V,
    public_pool: Option<&public_pool::FrozenPublicPoolProgramV3>,
) -> Result<(), RedemptionCapabilityErrorV2> {
    let public_scripts = public_pool.map(|policy| policy.validate(input.simplicity_program_bytes,context))
        .transpose().map_err(|_| RedemptionCapabilityErrorV2::Configuration)?;
    if public_scripts.is_some() {
        for leaf in [&inventory,&reserve] {
            if !matches!(leaf.utxo.output.asset,elements::confidential::Asset::Explicit(_))
                || !matches!(leaf.utxo.output.value,elements::confidential::Value::Explicit(_)) {
                return Err(RedemptionCapabilityErrorV2::Economics);
            }
        }
    }
    let configuration = context;
    let public = context;
    if input.public_values.is_empty() || input.simplicity_program_bytes.is_empty()
        || input.probe_transaction.is_empty()
        || input.probe_transaction.len() > MAX_REDEMPTION_CAPABILITY_INPUT_BYTES_V2
        || !(2..=3).contains(&input.probe_outputs.len()) || input.simplicity_receipts.len() != 2
        || context.child_genesis == [0;32] || context.simplicity_evaluator_program_id == [0;32]
        || context.quote_atoms_per_whole_base == 0 || context.source_tip_mtp == 0 {
        return Err(RedemptionCapabilityErrorV2::NonCanonicalInput);
    }
    for leaf in [&inventory, &reserve] {
        verify_elements_economic_leaf_v2(leaf, context.classification)
            .map_err(|_| RedemptionCapabilityErrorV2::Economics)?;
    }
    if inventory.role != ElementsLiveEconomicRoleV2::RedemptionInventory
        || reserve.role != ElementsLiveEconomicRoleV2::RedeemableReserve
        || inventory.utxo.outpoint == reserve.utxo.outpoint {
        return Err(RedemptionCapabilityErrorV2::Membership);
    }
    let holder = input
        .holder_base_input
        .decode()
        .map_err(|_| RedemptionCapabilityErrorV2::Economics)?;
    verify_elements_economic_leaf_v2(&holder, configuration.classification)
        .map_err(|_| RedemptionCapabilityErrorV2::Economics)?;

    let probe_base_atoms = u64::try_from(
        public
            .outstanding_base_atoms
            .min(BASE_ASSET_ATOMS_PER_WHOLE),
    )
    .map_err(|_| RedemptionCapabilityErrorV2::Economics)?;
    let required_quote_atoms = ceil_div(
        u128::from(probe_base_atoms)
            .checked_mul(u128::from(configuration.quote_atoms_per_whole_base))
            .ok_or(RedemptionCapabilityErrorV2::Economics)?,
        BASE_ASSET_ATOMS_PER_WHOLE,
    )?;
    let required_quote_atoms =
        u64::try_from(required_quote_atoms).map_err(|_| RedemptionCapabilityErrorV2::Economics)?;
    if probe_base_atoms == 0
        || required_quote_atoms == 0
        || holder.role != ElementsLiveEconomicRoleV2::OutstandingBase
        || holder.asset_id != configuration.classification.base_asset_id
        || holder.amount != probe_base_atoms
        || inventory.asset_id != configuration.classification.base_asset_id
        || reserve.asset_id != configuration.classification.policy_asset_id
    {
        return Err(RedemptionCapabilityErrorV2::Economics);
    }

    let transaction: Transaction = elements::encode::deserialize(&input.probe_transaction)
        .map_err(|_| RedemptionCapabilityErrorV2::NonCanonicalInput)?;
    if elements::encode::serialize(&transaction).as_slice() != input.probe_transaction
        || transaction.input.len() != 3
        || transaction.output.len() != input.probe_outputs.len()
        || transaction.input[0].previous_output != holder.utxo.outpoint
        || transaction.input[1].previous_output != inventory.utxo.outpoint
        || transaction.input[2].previous_output != reserve.utxo.outpoint
        || transaction
            .input
            .iter()
            .any(|value| value.is_pegin || value.asset_issuance != Default::default())
    {
        return Err(RedemptionCapabilityErrorV2::Economics);
    }
    // A completely redeemed reserve has no successor output. Requiring a
    // zero-valued economic leaf would reject otherwise fully covered redemption.
    let (successor_reserve, expected_outputs) = redemption_reserve_successor(
        reserve.amount, required_quote_atoms)?;
    if transaction.output.len() != expected_outputs {
        return Err(RedemptionCapabilityErrorV2::Economics);
    }
    let next_height = u32::try_from(
        public
            .source_tip_height
            .checked_add(1)
            .ok_or(RedemptionCapabilityErrorV2::Economics)?,
    )
    .map_err(|_| RedemptionCapabilityErrorV2::Economics)?;
    let parent_mtp =
        u32::try_from(public.source_tip_mtp).map_err(|_| RedemptionCapabilityErrorV2::Economics)?;
    let lock_spends = [holder.clone(), inventory.clone(), reserve.clone()]
        .into_iter()
        .map(|leaf| ElementsSparseUtxoMutationV2 {
            outpoint: leaf.utxo.outpoint,
            old_leaf: Some(leaf.utxo),
            new_leaf: None,
            path: ElementsSparseUtxoPathV2 { siblings: vec![] },
        })
        .collect::<Vec<_>>();
    verify_elements_transaction_locks_v2(
        &transaction,
        &lock_spends,
        ElementsTransactionSpendContextV2 {
            height: next_height,
            parent_mtp,
        },
    )
    .map_err(|_| RedemptionCapabilityErrorV2::CovenantExecution)?;

    let txid = transaction.txid();
    let outputs = input
        .probe_outputs
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let leaf = value
                .decode()
                .map_err(|_| RedemptionCapabilityErrorV2::Economics)?;
            if leaf.utxo.outpoint != OutPoint::new(txid, index as u32)
                || leaf.utxo.output != transaction.output[index]
            {
                return Err(RedemptionCapabilityErrorV2::Economics);
            }
            verify_elements_economic_leaf_v2(&leaf, configuration.classification)
                .map_err(|_| RedemptionCapabilityErrorV2::Economics)?;
            Ok(leaf)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let successor_inventory = inventory
        .amount
        .checked_add(probe_base_atoms)
        .ok_or(RedemptionCapabilityErrorV2::Economics)?;
    if outputs[0].role != ElementsLiveEconomicRoleV2::Irrelevant
        || outputs[0].asset_id != configuration.classification.policy_asset_id
        || outputs[0].amount != required_quote_atoms
        || outputs[1].role != ElementsLiveEconomicRoleV2::RedemptionInventory
        || outputs[1].asset_id != configuration.classification.base_asset_id
        || outputs[1].amount != successor_inventory
        || (successor_reserve != 0
            && (outputs[2].role != ElementsLiveEconomicRoleV2::RedeemableReserve
                || outputs[2].asset_id != configuration.classification.policy_asset_id
                || outputs[2].amount != successor_reserve))
    {
        return Err(RedemptionCapabilityErrorV2::Economics);
    }

    for input_index in [1usize, 2] {
        let stack = &transaction.input[input_index].witness.script_witness;
        let without_annex = if stack
            .last()
            .is_some_and(|value| value.first() == Some(&0x50))
        {
            &stack[..stack.len() - 1]
        } else {
            stack.as_slice()
        };
        let [covenant_witness, program, cmr, control] = without_annex else {
            return Err(RedemptionCapabilityErrorV2::CovenantExecution);
        };
        let witness_bound = if let (Some(policy),Some(scripts)) = (public_pool,public_scripts.as_ref()) {
            let expected_control = if input_index == 1 {&scripts.inventory_control} else {&scripts.reserve_control};
            covenant_witness.is_empty() && cmr.as_slice() == policy.compiled_cmr
                && *control == expected_control.serialize()
        } else { covenant_witness.starts_with(input.public_values) };
        if !witness_bound || program.as_slice() != input.simplicity_program_bytes {
            return Err(RedemptionCapabilityErrorV2::CovenantExecution);
        }
    }
    let simplicity = ProofCarryingElementsSimplicityExecutorV2::new(
        configuration.simplicity_evaluator_program_id,
        &input.simplicity_receipts,
        receipt_verifier,
    )
    .map_err(|_| RedemptionCapabilityErrorV2::CovenantExecution)?;
    let input_verifier = FullElementsInputVerifierWithSimplicityV2 {
        base: FullElementsInputVerifierV2::new(BlockHash::from_byte_array(
            configuration.child_genesis,
        )),
        simplicity: &simplicity,
    };
    let previous_outputs = vec![
        holder.utxo.output,
        inventory.utxo.output,
        reserve.utxo.output,
    ];
    transaction
        .verify_tx_amt_proofs(&Secp256k1::new(), &previous_outputs)
        .map_err(|_| RedemptionCapabilityErrorV2::Economics)?;
    for input_index in [1usize, 2] {
        input_verifier
            .verify_input(&transaction, input_index, &previous_outputs)
            .map_err(|_| RedemptionCapabilityErrorV2::CovenantExecution)?;
    }
    simplicity
        .require_all_receipts_consumed()
        .map_err(|_| RedemptionCapabilityErrorV2::CovenantExecution)?;
    Ok(())
}

fn authenticate_leaf(
    value: &AuthenticatedEconomicLeafV2,
    utxo_root: ElementsSparseUtxoNodeV2,
    economic_root: ElementsSparseEconomicNodeV2,
    classification: ecx_full_consensus_validator_v2::elements_v2::ElementsEconomicClassificationV2,
) -> Result<
    ecx_full_consensus_validator_v2::elements_v2::ElementsEconomicLeafV2,
    RedemptionCapabilityErrorV2,
> {
    let leaf = value
        .leaf
        .decode()
        .map_err(|_| RedemptionCapabilityErrorV2::Membership)?;
    let economic_node = verify_elements_economic_leaf_v2(&leaf, classification)
        .map_err(|_| RedemptionCapabilityErrorV2::Membership)?;
    if elements_sparse_utxo_root_from_path_v2(
        leaf.utxo.outpoint,
        elements_utxo_leaf_node_v2(&leaf.utxo),
        &value.utxo_path,
    )
    .map_err(|_| RedemptionCapabilityErrorV2::Membership)?
        != utxo_root
        || elements_sparse_economic_root_from_path_v2(
            leaf.utxo.outpoint,
            economic_node,
            &value.economic_path,
        )
        .map_err(|_| RedemptionCapabilityErrorV2::Membership)?
            != economic_root
    {
        return Err(RedemptionCapabilityErrorV2::Membership);
    }
    Ok(leaf)
}

fn redemption_reserve_successor(reserve: u64, payout: u64)
    -> Result<(u64, usize), RedemptionCapabilityErrorV2>
{
    if payout == 0 { return Err(RedemptionCapabilityErrorV2::Economics); }
    let remaining = reserve.checked_sub(payout)
        .ok_or(RedemptionCapabilityErrorV2::Economics)?;
    Ok((remaining, if remaining == 0 { 2 } else { 3 }))
}

#[cfg(test)]
mod full_redemption_tests {
    use super::*;

    #[test]
    fn depleted_reserve_is_omitted_and_nonzero_reserve_is_preserved() {
        assert_eq!(redemption_reserve_successor(100, 100).unwrap(), (0, 2));
        assert_eq!(redemption_reserve_successor(101, 100).unwrap(), (1, 3));
        assert_eq!(redemption_reserve_successor(u64::MAX, u64::MAX).unwrap(), (0, 2));
        assert!(redemption_reserve_successor(99, 100).is_err());
        assert!(redemption_reserve_successor(0, 0).is_err());
        assert!(redemption_reserve_successor(100, 0).is_err());
    }
}

fn ceil_div(numerator: u128, denominator: u128) -> Result<u128, RedemptionCapabilityErrorV2> {
    if denominator == 0 {
        return Err(RedemptionCapabilityErrorV2::Economics);
    }
    numerator
        .checked_add(denominator - 1)
        .map(|value| value / denominator)
        .ok_or(RedemptionCapabilityErrorV2::Economics)
}

fn validate_shape(input: &RedemptionCapabilityInputV2) -> Result<(), RedemptionCapabilityErrorV2> {
    if input.version != REDEMPTION_CAPABILITY_INPUT_VERSION_V2
        || input.public_values.is_empty()
        || input.configuration_preimage.is_empty()
        || input.probe_transaction.is_empty()
        || input.probe_outputs.len() != 3
        || input.simplicity_receipts.len() != 2
        || options()
            .serialized_size(input)
            .map_err(|_| RedemptionCapabilityErrorV2::NonCanonicalInput)?
            > MAX_REDEMPTION_CAPABILITY_INPUT_BYTES_V2 as u64
    {
        return Err(RedemptionCapabilityErrorV2::NonCanonicalInput);
    }
    for leaf in [
        &input.inventory.leaf,
        &input.reserve.leaf,
        &input.holder_base_input,
    ]
    .into_iter()
    .chain(&input.probe_outputs)
    {
        leaf.decode()
            .map_err(|_| RedemptionCapabilityErrorV2::NonCanonicalInput)?;
    }
    Ok(())
}

fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_big_endian()
        .with_limit(MAX_REDEMPTION_CAPABILITY_INPUT_BYTES_V2 as u64)
        .reject_trailing_bytes()
}

#[cfg(test)]
#[path = "wire_tests.rs"]
mod wire_tests;
