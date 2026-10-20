//! Fresh SP1 boundary for the one-shot pristine-state successor activation.

use ecx_protocol_core::{
    verify_incremental_empty_activation_v2, Hash32, IncrementalEmptyActivationConfigurationV2,
    IncrementalEmptyActivationWitnessV2, ProtocolError,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const INCREMENTAL_ACTIVATION_BINDING_VERSION_V2: u8 = 1;
pub const INCREMENTAL_ACTIVATION_PUBLIC_VALUES_VERSION_V2: u32 = 1;
pub const INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN_V2: usize = 4 + (10 * 32) + (5 * 8);
pub const MAX_INCREMENTAL_ACTIVATION_INPUT_BYTES_V2: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalActivationBindingV2 {
    pub version: u8,
    pub activation_transaction_txid: Hash32,
    pub prior_parent_block_hash: Hash32,
    pub expected_activation_configuration_hash: Hash32,
    pub expected_finite_v18_configuration_hash: Hash32,
    pub expected_finite_v18_state_root: Hash32,
    pub expected_successor_configuration_hash: Hash32,
    pub expected_successor_state_root: Hash32,
    pub expected_chain_id: Hash32,
    pub activation_sidechain_height: u64,
    pub activation_parent_mtp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalActivationProofInputV2 {
    pub binding: IncrementalActivationBindingV2,
    pub configuration: IncrementalEmptyActivationConfigurationV2,
    pub witness: IncrementalEmptyActivationWitnessV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalActivationPublicValuesV2 {
    pub activation_configuration_hash: Hash32,
    pub finite_v18_configuration_hash: Hash32,
    pub finite_v18_state_root: Hash32,
    pub successor_configuration_hash: Hash32,
    pub successor_state_root: Hash32,
    pub activation_transaction_txid: Hash32,
    pub prior_parent_block_hash: Hash32,
    pub chain_id: Hash32,
    pub bond_state_root: Hash32,
    pub funding_state_root: Hash32,
    pub activation_sidechain_height: u64,
    pub activation_parent_mtp: u64,
    pub mark_price_atoms: u64,
    pub price_lower_atoms: u64,
    pub price_upper_atoms: u64,
}

impl IncrementalActivationPublicValuesV2 {
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN_V2);
        out.extend_from_slice(&INCREMENTAL_ACTIVATION_PUBLIC_VALUES_VERSION_V2.to_be_bytes());
        for hash in [
            self.activation_configuration_hash,
            self.finite_v18_configuration_hash,
            self.finite_v18_state_root,
            self.successor_configuration_hash,
            self.successor_state_root,
            self.activation_transaction_txid,
            self.prior_parent_block_hash,
            self.chain_id,
            self.bond_state_root,
            self.funding_state_root,
        ] {
            out.extend_from_slice(&hash);
        }
        for value in [
            self.activation_sidechain_height,
            self.activation_parent_mtp,
            self.mark_price_atoms,
            self.price_lower_atoms,
            self.price_upper_atoms,
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        debug_assert_eq!(out.len(), INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN_V2);
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncrementalActivationProofResultV2 {
    pub public: IncrementalActivationPublicValuesV2,
    pub public_values: Vec<u8>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IncrementalActivationProofErrorV2 {
    #[error("incremental activation binding is invalid")]
    InvalidBinding,
    #[error("incremental activation relation rejected: {0}")]
    Protocol(#[from] ProtocolError),
}

fn nonzero(hash: Hash32) -> bool {
    hash != [0; 32]
}

pub fn execute_incremental_activation_proof_v2(
    input: &IncrementalActivationProofInputV2,
) -> Result<IncrementalActivationProofResultV2, IncrementalActivationProofErrorV2> {
    let binding = &input.binding;
    let successor = &input.witness.successor_state;
    if binding.version != INCREMENTAL_ACTIVATION_BINDING_VERSION_V2
        || !nonzero(binding.activation_transaction_txid)
        || !nonzero(binding.prior_parent_block_hash)
        || !nonzero(binding.expected_activation_configuration_hash)
        || !nonzero(binding.expected_finite_v18_configuration_hash)
        || !nonzero(binding.expected_finite_v18_state_root)
        || !nonzero(binding.expected_successor_configuration_hash)
        || !nonzero(binding.expected_successor_state_root)
        || !nonzero(binding.expected_chain_id)
        || binding.activation_sidechain_height == 0
        || binding.activation_parent_mtp == 0
    {
        return Err(IncrementalActivationProofErrorV2::InvalidBinding);
    }

    let result = verify_incremental_empty_activation_v2(input.configuration, &input.witness)?;
    let successor_configuration_hash = input.configuration.successor.digest()?;
    if binding.expected_activation_configuration_hash != result.activation_configuration_hash
        || binding.expected_finite_v18_configuration_hash
            != input.configuration.finite_v18_configuration_hash
        || binding.expected_finite_v18_state_root != result.finite_v18_state_root
        || binding.expected_successor_configuration_hash != successor_configuration_hash
        || binding.expected_successor_state_root != result.successor_state_root
        || binding.expected_chain_id != input.configuration.successor.chain_id
        || binding.activation_sidechain_height != successor.sidechain_height
        || binding.activation_parent_mtp != successor.parent_median_time_past
    {
        return Err(IncrementalActivationProofErrorV2::InvalidBinding);
    }

    let public = IncrementalActivationPublicValuesV2 {
        activation_configuration_hash: result.activation_configuration_hash,
        finite_v18_configuration_hash: input.configuration.finite_v18_configuration_hash,
        finite_v18_state_root: result.finite_v18_state_root,
        successor_configuration_hash,
        successor_state_root: result.successor_state_root,
        activation_transaction_txid: binding.activation_transaction_txid,
        prior_parent_block_hash: binding.prior_parent_block_hash,
        chain_id: input.configuration.successor.chain_id,
        bond_state_root: successor.bond_state_root,
        funding_state_root: successor.funding_state_root,
        activation_sidechain_height: successor.sidechain_height,
        activation_parent_mtp: successor.parent_median_time_past,
        mark_price_atoms: successor.mark_price_atoms,
        price_lower_atoms: successor.price_lower_atoms,
        price_upper_atoms: successor.price_upper_atoms,
    };
    Ok(IncrementalActivationProofResultV2 {
        public_values: public.encode(),
        public,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_values_are_fixed_width_and_positionally_bound() {
        let public = IncrementalActivationPublicValuesV2 {
            activation_configuration_hash: [1; 32],
            finite_v18_configuration_hash: [2; 32],
            finite_v18_state_root: [3; 32],
            successor_configuration_hash: [4; 32],
            successor_state_root: [5; 32],
            activation_transaction_txid: [6; 32],
            prior_parent_block_hash: [7; 32],
            chain_id: [8; 32],
            bond_state_root: [9; 32],
            funding_state_root: [10; 32],
            activation_sidechain_height: 11,
            activation_parent_mtp: 12,
            mark_price_atoms: 13,
            price_lower_atoms: 14,
            price_upper_atoms: 15,
        };
        let encoded = public.encode();
        assert_eq!(encoded.len(), INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN_V2);
        assert_eq!(&encoded[..4], &1u32.to_be_bytes());
        assert_eq!(&encoded[4..36], &[1; 32]);
        assert_eq!(&encoded[292..324], &[10; 32]);
        assert_eq!(&encoded[324..332], &11u64.to_be_bytes());
        assert_eq!(&encoded[356..364], &15u64.to_be_bytes());
    }
}
