//! Preparation of the rolling ownerless-USDD checkpoint authority state.
//!
//! A verified Ethereum receipt supplies every new Ethereum field. Neither a
//! host-selected checkpoint preimage nor an `authenticated` boolean is an
//! input. The prior authority state and accepting BMM parent MTP remain inputs
//! of the enclosing, fully executed Elements relation. This preparation does
//! NOT prove that either belongs to the chain or that an authority was spent.

use ecx_protocol_core::{verify_usdd_checkpoint_successor, UsddEthereumCheckpointV1};

use crate::usdd_usd_ownerless_v3::{
    FrozenOwnerlessConversionConfigurationV3, OwnerlessConversionErrorV3,
    OwnerlessEthereumPublicValuesV3, OwnerlessSourceReceiptVerifierV3,
};

/// Exact preimages ready for authority-transaction construction/execution.
/// Private fields prevent bypassing receipt verification through a literal.
/// This is intentionally not an authenticated Elements state or a source
/// journal: inclusion, prior-UTXO membership and covenant execution are absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedOwnerlessCheckpointTransitionV3 {
    prior: UsddEthereumCheckpointV1,
    successor: UsddEthereumCheckpointV1,
}

impl PreparedOwnerlessCheckpointTransitionV3 {
    pub fn prior(&self) -> &UsddEthereumCheckpointV1 {
        &self.prior
    }

    pub fn successor(&self) -> &UsddEthereumCheckpointV1 {
        &self.successor
    }
}

/// Verify the frozen Ethereum source role, cross-bind its exact previous
/// finalized state, and derive the next checkpoint without caller-selected
/// Ethereum values. This is a preparation boundary, NOT a complete producer.
///
/// The calling guest must separately authenticate `prior` from its current
/// authority UTXO and `accepting_parent_mtp` from the parent/BMM relation, render
/// state-bound scripts, check the exact spend/recreate settlement, and execute
/// that transaction against authenticated prevouts. No readiness or authority
/// flag is set here. A host diagnostic must not label the returned state live.
pub fn prepare_ownerless_checkpoint_transition_v3<V: OwnerlessSourceReceiptVerifierV3>(
    configuration: &FrozenOwnerlessConversionConfigurationV3,
    prior: &UsddEthereumCheckpointV1,
    ethereum: &OwnerlessEthereumPublicValuesV3,
    ethereum_proof_marker: &[u8],
    accepting_parent_mtp: u64,
    verifier: &V,
) -> Result<PreparedOwnerlessCheckpointTransitionV3, OwnerlessConversionErrorV3> {
    configuration.validate()?;
    ethereum.validate_shape()?;
    ethereum.validate_accounting()?;
    // The same exact deferred-marker size as the existing outer envelope.
    if ethereum_proof_marker.len() != 32 {
        return Err(OwnerlessConversionErrorV3::EthereumProof);
    }
    if ethereum.frozen_configuration_commitment != configuration.source.commitment()
        || ethereum.protocol_manifest_commitment != configuration.protocol_manifest_commitment
    {
        return Err(OwnerlessConversionErrorV3::Binding);
    }
    let checkpoint_configuration = configuration.checkpoint_configuration();
    prior
        .validate(&checkpoint_configuration)
        .map_err(|_| OwnerlessConversionErrorV3::Checkpoint)?;
    if ethereum.prior_light_client_digest != prior.light_client_digest
        || ethereum.prior_finalized_beacon_slot != prior.finalized_beacon_slot
        || ethereum.prior_finalized_beacon_root != prior.finalized_beacon_root
        || ethereum.prior_finalized_execution_state_root != prior.finalized_execution_state_root
    {
        return Err(OwnerlessConversionErrorV3::Checkpoint);
    }
    let successor = UsddEthereumCheckpointV1 {
        version: UsddEthereumCheckpointV1::VERSION,
        configuration_hash: checkpoint_configuration.digest(),
        sequence: prior
            .sequence
            .checked_add(1)
            .ok_or(OwnerlessConversionErrorV3::Checkpoint)?,
        light_client_digest: ethereum.light_client_digest,
        finalized_beacon_slot: ethereum.finalized_beacon_slot,
        finalized_beacon_root: ethereum.finalized_beacon_root,
        finalized_execution_block_hash: ethereum.finalized_execution_block_hash,
        finalized_execution_state_root: ethereum.finalized_execution_state_root,
        finalized_execution_block_number: ethereum.execution_block_number,
        finalized_execution_timestamp: ethereum.execution_block_timestamp,
        accepted_parent_mtp: accepting_parent_mtp,
        prior_checkpoint_commitment: prior.commitment(),
        update_proof_commitment: ethereum.update_proof_commitment,
    };
    verify_usdd_checkpoint_successor(&checkpoint_configuration, prior, &successor)
        .map_err(|_| OwnerlessConversionErrorV3::Checkpoint)?;
    verifier.verify_ethereum(
        configuration.ethereum_source_program_id,
        &ethereum.canonical_bytes(),
        ethereum_proof_marker,
    )?;
    Ok(PreparedOwnerlessCheckpointTransitionV3 {
        prior: *prior,
        successor,
    })
}
