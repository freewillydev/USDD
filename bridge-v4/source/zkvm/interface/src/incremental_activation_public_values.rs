use sha2::{Digest, Sha256};
use std::fmt;

pub const INCREMENTAL_ACTIVATION_PUBLIC_VALUES_VERSION_V2: u32 = 1;
pub const INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN_V2: usize = 4 + (10 * 32) + (5 * 8);

/// Independent consensus-side representation of the one-shot pristine V18 to
/// incremental-successor activation statement. This is deliberately distinct
/// from `PublicValuesV5`: normal V18 transitions and the one-shot migration do
/// not share a proof program, state layout, or annex version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IncrementalActivationPublicValuesV2 {
    pub activation_configuration_hash: [u8; 32],
    pub finite_v18_configuration_hash: [u8; 32],
    pub finite_v18_state_root: [u8; 32],
    pub successor_configuration_hash: [u8; 32],
    pub successor_state_root: [u8; 32],
    pub activation_transaction_txid: [u8; 32],
    pub prior_parent_block_hash: [u8; 32],
    pub chain_id: [u8; 32],
    pub bond_state_root: [u8; 32],
    pub funding_state_root: [u8; 32],
    pub activation_sidechain_height: u64,
    pub activation_parent_mtp: u64,
    pub mark_price_atoms: u64,
    pub price_lower_atoms: u64,
    pub price_upper_atoms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IncrementalActivationPublicValuesError {
    WrongLength,
    UnsupportedVersion,
    ZeroIdentity,
    CollidingConfigurationIdentity,
    InvalidParentContext,
    InvalidPriceRange,
}

impl fmt::Display for IncrementalActivationPublicValuesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid ECX incremental activation public values: {self:?}"
        )
    }
}

impl std::error::Error for IncrementalActivationPublicValuesError {}

impl IncrementalActivationPublicValuesV2 {
    pub fn encode(&self) -> [u8; INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN_V2] {
        let mut output = [0_u8; INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN_V2];
        output[0..4]
            .copy_from_slice(&INCREMENTAL_ACTIVATION_PUBLIC_VALUES_VERSION_V2.to_be_bytes());
        let hashes = [
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
        ];
        for (index, hash) in hashes.iter().enumerate() {
            let start = 4 + (index * 32);
            output[start..start + 32].copy_from_slice(hash);
        }
        let values = [
            self.activation_sidechain_height,
            self.activation_parent_mtp,
            self.mark_price_atoms,
            self.price_lower_atoms,
            self.price_upper_atoms,
        ];
        for (index, value) in values.iter().enumerate() {
            let start = 324 + (index * 8);
            output[start..start + 8].copy_from_slice(&value.to_be_bytes());
        }
        output
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IncrementalActivationPublicValuesError> {
        if bytes.len() != INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN_V2 {
            return Err(IncrementalActivationPublicValuesError::WrongLength);
        }
        if u32::from_be_bytes(bytes[0..4].try_into().expect("four-byte version"))
            != INCREMENTAL_ACTIVATION_PUBLIC_VALUES_VERSION_V2
        {
            return Err(IncrementalActivationPublicValuesError::UnsupportedVersion);
        }
        let mut hashes = [[0_u8; 32]; 10];
        for (index, hash) in hashes.iter_mut().enumerate() {
            let start = 4 + (index * 32);
            hash.copy_from_slice(&bytes[start..start + 32]);
        }
        if hashes.contains(&[0; 32]) {
            return Err(IncrementalActivationPublicValuesError::ZeroIdentity);
        }
        if hashes[0] == hashes[1] || hashes[0] == hashes[3] || hashes[1] == hashes[3] {
            return Err(IncrementalActivationPublicValuesError::CollidingConfigurationIdentity);
        }
        let mut values = [0_u64; 5];
        for (index, value) in values.iter_mut().enumerate() {
            let start = 324 + (index * 8);
            *value = u64::from_be_bytes(bytes[start..start + 8].try_into().expect("eight bytes"));
        }
        if values[0] == 0 || values[1] == 0 {
            return Err(IncrementalActivationPublicValuesError::InvalidParentContext);
        }
        if values[2] == 0
            || values[3] == 0
            || values[4] == 0
            || values[3] > values[2]
            || values[2] > values[4]
        {
            return Err(IncrementalActivationPublicValuesError::InvalidPriceRange);
        }
        Ok(Self {
            activation_configuration_hash: hashes[0],
            finite_v18_configuration_hash: hashes[1],
            finite_v18_state_root: hashes[2],
            successor_configuration_hash: hashes[3],
            successor_state_root: hashes[4],
            activation_transaction_txid: hashes[5],
            prior_parent_block_hash: hashes[6],
            chain_id: hashes[7],
            bond_state_root: hashes[8],
            funding_state_root: hashes[9],
            activation_sidechain_height: values[0],
            activation_parent_mtp: values[1],
            mark_price_atoms: values[2],
            price_lower_atoms: values[3],
            price_upper_atoms: values[4],
        })
    }

    pub fn sha256(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }
}
