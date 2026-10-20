//! Rolling finalized-Ethereum checkpoint used by USDD collateral.
//!
//! This module defines the consensus-shaped state and rollover rules. The mock
//! deployment supplies deterministic proof commitments; a real USDD deployment
//! must freeze and verify the Ethereum light-client program identified by the
//! configuration hash.

use crate::codec::{put_u64, put_u8, CanonicalEncode};
use crate::{tagged_hash, AnchorOutpointV1, Hash32, ProtocolError};

/// USDD's maximum permitted finalized-checkpoint age: thirteen days.
pub const USDD_MAX_CHECKPOINT_AGE_SECONDS: u64 = 13 * 24 * 60 * 60;

pub fn usdd_checkpoint_authority_configuration_hash(
    authority_asset_id: Hash32,
    authority_amount: u64,
    script_tree_configuration_hash: Hash32,
    policy_asset_id: Hash32,
) -> Hash32 {
    let mut bytes = Vec::with_capacity(104);
    bytes.extend_from_slice(&authority_asset_id);
    put_u64(&mut bytes, authority_amount);
    bytes.extend_from_slice(&script_tree_configuration_hash);
    bytes.extend_from_slice(&policy_asset_id);
    tagged_hash("ECX/usdd-checkpoint-authority/v1", &bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UsddCheckpointConfigV1 {
    pub version: u8,
    /// Identifies the Ethereum network and finalized-light-client verifier.
    pub ethereum_light_client_configuration_hash: Hash32,
    /// Identifies the spend-and-recreate Elements authority script and asset.
    pub authority_configuration_hash: Hash32,
    /// May be shorter, but never longer, than the USDD thirteen-day rule.
    pub maximum_checkpoint_age_seconds: u64,
}

impl UsddCheckpointConfigV1 {
    pub const VERSION: u8 = 1;

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION
            || self.ethereum_light_client_configuration_hash == [0; 32]
            || self.authority_configuration_hash == [0; 32]
            || self.ethereum_light_client_configuration_hash == self.authority_configuration_hash
            || self.maximum_checkpoint_age_seconds == 0
            || self.maximum_checkpoint_age_seconds > USDD_MAX_CHECKPOINT_AGE_SECONDS
        {
            return Err(ProtocolError::InvalidUsddCheckpoint);
        }
        Ok(())
    }

    pub fn digest(&self) -> Hash32 {
        tagged_hash(
            "ECX/usdd-checkpoint-configuration/v1",
            &self.canonical_bytes(),
        )
    }
}

impl CanonicalEncode for UsddCheckpointConfigV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.ethereum_light_client_configuration_hash);
        out.extend_from_slice(&self.authority_configuration_hash);
        put_u64(out, self.maximum_checkpoint_age_seconds);
    }
}

/// Complete finalized checkpoint recreated by each accepted Elements update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UsddEthereumCheckpointV1 {
    pub version: u8,
    pub configuration_hash: Hash32,
    pub sequence: u64,
    pub light_client_digest: Hash32,
    pub finalized_beacon_slot: u64,
    pub finalized_beacon_root: Hash32,
    pub finalized_execution_block_hash: Hash32,
    pub finalized_execution_state_root: Hash32,
    pub finalized_execution_block_number: u64,
    pub finalized_execution_timestamp: u64,
    /// Authenticated BMM parent MTP available to the accepting Elements tx.
    pub accepted_parent_mtp: u64,
    pub prior_checkpoint_commitment: Hash32,
    /// Commitment to the exact light-client update proof/public values.
    pub update_proof_commitment: Hash32,
}

impl UsddEthereumCheckpointV1 {
    pub const VERSION: u8 = 1;

    pub fn validate(&self, config: &UsddCheckpointConfigV1) -> Result<(), ProtocolError> {
        config.validate()?;
        if self.version != Self::VERSION
            || self.configuration_hash != config.digest()
            || self.finalized_beacon_slot == 0
            || self.finalized_execution_block_number == 0
            || self.finalized_execution_timestamp == 0
            || self.accepted_parent_mtp < self.finalized_execution_timestamp
            || self
                .accepted_parent_mtp
                .checked_sub(self.finalized_execution_timestamp)
                .ok_or(ProtocolError::ArithmeticOverflow)?
                > config.maximum_checkpoint_age_seconds
            || [
                self.light_client_digest,
                self.finalized_beacon_root,
                self.finalized_execution_block_hash,
                self.finalized_execution_state_root,
                self.update_proof_commitment,
            ]
            .contains(&[0; 32])
            || (self.sequence == 0 && self.prior_checkpoint_commitment != [0; 32])
            || (self.sequence != 0 && self.prior_checkpoint_commitment == [0; 32])
        {
            return Err(ProtocolError::InvalidUsddCheckpoint);
        }
        Ok(())
    }

    pub fn commitment(&self) -> Hash32 {
        tagged_hash("ECX/usdd-ethereum-checkpoint/v1", &self.canonical_bytes())
    }

    /// Whether this accepted checkpoint is still usable at authenticated MTP.
    pub fn is_current(
        &self,
        config: &UsddCheckpointConfigV1,
        authenticated_parent_mtp: u64,
    ) -> bool {
        self.validate(config).is_ok()
            // A checkpoint cannot be used before the authenticated parent
            // context in which its authority transition was accepted. Merely
            // being newer than its Ethereum execution timestamp is not enough.
            && authenticated_parent_mtp >= self.accepted_parent_mtp
            && authenticated_parent_mtp - self.finalized_execution_timestamp
                <= config.maximum_checkpoint_age_seconds
    }
}

impl CanonicalEncode for UsddEthereumCheckpointV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.configuration_hash);
        put_u64(out, self.sequence);
        out.extend_from_slice(&self.light_client_digest);
        put_u64(out, self.finalized_beacon_slot);
        out.extend_from_slice(&self.finalized_beacon_root);
        out.extend_from_slice(&self.finalized_execution_block_hash);
        out.extend_from_slice(&self.finalized_execution_state_root);
        put_u64(out, self.finalized_execution_block_number);
        put_u64(out, self.finalized_execution_timestamp);
        put_u64(out, self.accepted_parent_mtp);
        out.extend_from_slice(&self.prior_checkpoint_commitment);
        out.extend_from_slice(&self.update_proof_commitment);
    }
}

/// Transaction identity bound by the mock/real light-client update proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UsddCheckpointUpdateV1 {
    pub version: u8,
    pub prior_authority_outpoint: AnchorOutpointV1,
    pub successor_transaction_id: Hash32,
    pub successor_authority_output_index: u32,
}

impl UsddCheckpointUpdateV1 {
    pub const VERSION: u8 = 1;

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION
            || self.prior_authority_outpoint.txid == [0; 32]
            || self.successor_transaction_id == [0; 32]
            || self.successor_authority_output_index != 0
        {
            return Err(ProtocolError::InvalidUsddCheckpointSuccessor);
        }
        Ok(())
    }
}

/// Verifies the transaction-chain linkage between two recreated checkpoints.
pub fn verify_usdd_checkpoint_successor(
    config: &UsddCheckpointConfigV1,
    prior: &UsddEthereumCheckpointV1,
    successor: &UsddEthereumCheckpointV1,
) -> Result<(), ProtocolError> {
    prior.validate(config)?;
    successor.validate(config)?;
    if successor.sequence
        != prior
            .sequence
            .checked_add(1)
            .ok_or(ProtocolError::ArithmeticOverflow)?
        || successor.prior_checkpoint_commitment != prior.commitment()
        || successor.finalized_beacon_slot <= prior.finalized_beacon_slot
        || successor.finalized_execution_block_number <= prior.finalized_execution_block_number
        || successor.finalized_execution_timestamp <= prior.finalized_execution_timestamp
        || successor.accepted_parent_mtp < prior.accepted_parent_mtp
        || successor.update_proof_commitment == prior.update_proof_commitment
    {
        return Err(ProtocolError::InvalidUsddCheckpointSuccessor);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> UsddCheckpointConfigV1 {
        UsddCheckpointConfigV1 {
            version: 1,
            ethereum_light_client_configuration_hash: [1; 32],
            authority_configuration_hash: [2; 32],
            maximum_checkpoint_age_seconds: USDD_MAX_CHECKPOINT_AGE_SECONDS,
        }
    }

    fn genesis() -> UsddEthereumCheckpointV1 {
        let config = config();
        UsddEthereumCheckpointV1 {
            version: 1,
            configuration_hash: config.digest(),
            sequence: 0,
            light_client_digest: [3; 32],
            finalized_beacon_slot: 100,
            finalized_beacon_root: [4; 32],
            finalized_execution_block_hash: [5; 32],
            finalized_execution_state_root: [6; 32],
            finalized_execution_block_number: 1_000,
            finalized_execution_timestamp: 10_000,
            accepted_parent_mtp: 10_060,
            prior_checkpoint_commitment: [0; 32],
            update_proof_commitment: [7; 32],
        }
    }

    fn successor(prior: &UsddEthereumCheckpointV1) -> UsddEthereumCheckpointV1 {
        UsddEthereumCheckpointV1 {
            sequence: prior.sequence + 1,
            light_client_digest: [8; 32],
            finalized_beacon_slot: prior.finalized_beacon_slot + 32,
            finalized_beacon_root: [9; 32],
            finalized_execution_block_hash: [10; 32],
            finalized_execution_state_root: [11; 32],
            finalized_execution_block_number: prior.finalized_execution_block_number + 20,
            finalized_execution_timestamp: prior.finalized_execution_timestamp + 240,
            accepted_parent_mtp: prior.accepted_parent_mtp + 240,
            prior_checkpoint_commitment: prior.commitment(),
            update_proof_commitment: [12; 32],
            ..*prior
        }
    }

    #[test]
    fn complete_checkpoint_rolls_forward_and_expires_after_thirteen_days() {
        let config = config();
        let prior = genesis();
        let next = successor(&prior);
        verify_usdd_checkpoint_successor(&config, &prior, &next).unwrap();
        assert!(next.is_current(
            &config,
            next.finalized_execution_timestamp + USDD_MAX_CHECKPOINT_AGE_SECONDS
        ));
        assert!(!next.is_current(
            &config,
            next.finalized_execution_timestamp + USDD_MAX_CHECKPOINT_AGE_SECONDS + 1
        ));
    }

    #[test]
    fn stale_new_checkpoint_and_broken_transaction_chain_reject() {
        let config = config();
        let prior = genesis();
        let mut stale = successor(&prior);
        stale.accepted_parent_mtp =
            stale.finalized_execution_timestamp + USDD_MAX_CHECKPOINT_AGE_SECONDS + 1;
        assert_eq!(
            verify_usdd_checkpoint_successor(&config, &prior, &stale),
            Err(ProtocolError::InvalidUsddCheckpoint)
        );

        let mut unlinked = successor(&prior);
        unlinked.prior_checkpoint_commitment[0] ^= 1;
        assert_eq!(
            verify_usdd_checkpoint_successor(&config, &prior, &unlinked),
            Err(ProtocolError::InvalidUsddCheckpointSuccessor)
        );
    }

    #[test]
    fn checkpoint_cannot_be_used_before_its_acceptance_context() {
        let config = config();
        let checkpoint = genesis();
        assert!(checkpoint.accepted_parent_mtp > checkpoint.finalized_execution_timestamp);
        assert!(!checkpoint.is_current(&config, checkpoint.finalized_execution_timestamp));
        assert!(!checkpoint.is_current(&config, checkpoint.accepted_parent_mtp - 1));
        assert!(checkpoint.is_current(&config, checkpoint.accepted_parent_mtp));
        assert!(checkpoint.is_current(&config,
            checkpoint.finalized_execution_timestamp + USDD_MAX_CHECKPOINT_AGE_SECONDS));
        assert!(!checkpoint.is_current(&config,
            checkpoint.finalized_execution_timestamp + USDD_MAX_CHECKPOINT_AGE_SECONDS + 1));
    }

    #[test]
    fn replay_regression_and_loose_cadence_reject() {
        let mut invalid_config = config();
        invalid_config.maximum_checkpoint_age_seconds = USDD_MAX_CHECKPOINT_AGE_SECONDS + 1;
        assert_eq!(
            invalid_config.validate(),
            Err(ProtocolError::InvalidUsddCheckpoint)
        );

        let config = config();
        let prior = genesis();
        let mut replay = successor(&prior);
        replay.finalized_beacon_slot = prior.finalized_beacon_slot;
        assert_eq!(
            verify_usdd_checkpoint_successor(&config, &prior, &replay),
            Err(ProtocolError::InvalidUsddCheckpointSuccessor)
        );
    }

    #[test]
    fn checkpointed_mock_usdd_python_bootstrap_vector_matches() {
        let genesis = [1; 32];
        let policy = [2; 32];
        let authority = [4; 32];
        let ethereum = tagged_hash("ECX/mock-usdd/ethereum-light-client/v1", &genesis);
        let mut script_material = genesis.to_vec();
        script_material.extend_from_slice(&authority);
        let script_tree = tagged_hash(
            "ECX/mock-usdd/checkpoint-script-profile/v1",
            &script_material,
        );
        let authority_hash =
            usdd_checkpoint_authority_configuration_hash(authority, 1, script_tree, policy);
        assert_eq!(
            authority_hash,
            [
                0x6d, 0x77, 0xb4, 0x20, 0xca, 0x11, 0x93, 0x92, 0x1e, 0x86, 0x2d, 0x18, 0x9c, 0x9b,
                0x73, 0xfe, 0x8a, 0x83, 0xc4, 0x2e, 0x87, 0x65, 0x3a, 0x41, 0xa2, 0xa7, 0x7a, 0x49,
                0xf4, 0x03, 0xcf, 0xcb,
            ]
        );
        let config = UsddCheckpointConfigV1 {
            version: 1,
            ethereum_light_client_configuration_hash: ethereum,
            authority_configuration_hash: authority_hash,
            maximum_checkpoint_age_seconds: USDD_MAX_CHECKPOINT_AGE_SECONDS,
        };
        assert_eq!(
            config.digest(),
            [
                0xc6, 0xae, 0xa8, 0xd2, 0xff, 0xef, 0x12, 0x85, 0x8f, 0x90, 0x90, 0x56, 0x34, 0x94,
                0x3b, 0x2d, 0x55, 0xca, 0x72, 0x72, 0xd2, 0xee, 0xfd, 0x67, 0x2d, 0xe8, 0xa2, 0xae,
                0x81, 0xef, 0x50, 0xfc,
            ]
        );
        let context = [
            genesis.as_slice(),
            100_u64.to_be_bytes().as_slice(),
            1_700_000_000_u64.to_be_bytes().as_slice(),
        ]
        .concat();
        let state = UsddEthereumCheckpointV1 {
            version: 1,
            configuration_hash: config.digest(),
            sequence: 0,
            light_client_digest: tagged_hash("ECX/mock-usdd/light-client-digest/v1", &context),
            finalized_beacon_slot: 100,
            finalized_beacon_root: tagged_hash("ECX/mock-usdd/finalized-beacon-root/v1", &context),
            finalized_execution_block_hash: tagged_hash(
                "ECX/mock-usdd/execution-block/v1",
                &context,
            ),
            finalized_execution_state_root: tagged_hash(
                "ECX/mock-usdd/execution-state/v1",
                &context,
            ),
            finalized_execution_block_number: 100,
            finalized_execution_timestamp: 1_700_000_000,
            accepted_parent_mtp: 1_700_000_000,
            prior_checkpoint_commitment: [0; 32],
            update_proof_commitment: tagged_hash("ECX/mock-usdd/update-proof/v1", &context),
        };
        assert_eq!(
            state.commitment(),
            [
                0xb7, 0x87, 0x3c, 0xe7, 0xad, 0xd6, 0xe5, 0xa8, 0x86, 0xec, 0x2d, 0xf8, 0x8d, 0x5c,
                0xaa, 0xef, 0x3d, 0x0c, 0x1e, 0xd9, 0x4c, 0x0d, 0x66, 0xa7, 0x43, 0xc1, 0x62, 0x46,
                0xcc, 0x0c, 0x87, 0xc2,
            ]
        );
    }
}
