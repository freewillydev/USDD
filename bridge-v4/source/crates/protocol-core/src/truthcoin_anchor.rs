//! Rolling, proof-authenticated Truthcoin checkpoint carried by an Elements
//! spend-and-recreate authority singleton.

use crate::codec::{put_u32, put_u64, put_u8, CanonicalEncode};
use crate::oracle::TruthcoinAuthenticationConfigV1;
use crate::{tagged_hash, Hash32, ProtocolError};

/// Frozen on-chain authority profile for the rolling Truthcoin checkpoint.
/// `script_tree_configuration_hash` commits the reviewed keyless internal key,
/// Simplicity leaf identity/version, topology, and state-node derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TruthcoinAnchorDeploymentV1 {
    pub version: u8,
    pub authority_asset_id: Hash32,
    pub authority_amount: u64,
    pub script_tree_configuration_hash: Hash32,
}

impl TruthcoinAnchorDeploymentV1 {
    pub const VERSION: u8 = 1;

    pub fn validate(&self, policy_asset_id: Hash32) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION
            || self.authority_asset_id == [0; 32]
            || self.authority_asset_id == policy_asset_id
            || self.authority_amount == 0
            || self.script_tree_configuration_hash == [0; 32]
        {
            return Err(ProtocolError::InvalidTruthcoinAnchor);
        }
        Ok(())
    }
}

impl CanonicalEncode for TruthcoinAnchorDeploymentV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.authority_asset_id);
        put_u64(out, self.authority_amount);
        out.extend_from_slice(&self.script_tree_configuration_hash);
    }
}

/// Complete configuration identity stored in each rolling anchor state. It
/// binds source-chain replay/authentication and the concrete Elements authority
/// deployment without introducing a self-referential full-config hash.
pub fn truthcoin_anchor_configuration_hash(
    authentication: &TruthcoinAuthenticationConfigV1,
    deployment: &TruthcoinAnchorDeploymentV1,
    policy_asset_id: Hash32,
) -> Hash32 {
    let mut bytes = authentication.canonical_bytes();
    deployment.encode_to(&mut bytes);
    bytes.extend_from_slice(&policy_asset_id);
    tagged_hash("ECX/truthcoin-anchor-configuration/v1", &bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AnchorOutpointV1 {
    pub txid: Hash32,
    pub vout: u32,
}

impl CanonicalEncode for AnchorOutpointV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.txid);
        put_u32(out, self.vout);
    }
}

/// Consensus commitment carried by the active Truthcoin authority output.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TruthcoinAnchorStateV1 {
    pub version: u8,
    pub configuration_hash: Hash32,
    pub sequence: u64,
    pub bitcoin_checkpoint_hash: Hash32,
    pub bitcoin_checkpoint_height: u64,
    pub bitcoin_checkpoint_mtp: u64,
    /// Unsigned 256-bit cumulative work in big-endian order.
    pub bitcoin_checkpoint_chainwork: Hash32,
    pub truthcoin_genesis_hash: Hash32,
    pub truthcoin_tip_hash: Hash32,
    pub truthcoin_tip_height: u64,
    pub truthcoin_tip_parent_bitcoin_hash: Hash32,
    pub canonical_path_root: Hash32,
    pub replay_transcript_root: Hash32,
    pub complete_state_root: Hash32,
    pub decision_registry_root: Hash32,
    pub market_registry_root: Hash32,
    pub lmsr_state_root: Hash32,
    pub sample_window_root: Hash32,
    pub selected_anchor_commitment: Hash32,
    pub selected_fast_market_commitment: Hash32,
    pub oracle_certificate_commitment: Hash32,
    pub last_update_elements_height: u64,
    pub source_data_available_through_height: u64,
    pub cumulative_update_root: Hash32,
    pub last_update_proof_commitment: Hash32,
}

impl TruthcoinAnchorStateV1 {
    pub const VERSION: u8 = 1;

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION {
            return Err(ProtocolError::UnsupportedVersion);
        }
        if self.bitcoin_checkpoint_height == 0
            || self.bitcoin_checkpoint_mtp == 0
            || self.last_update_elements_height == 0
            || self.source_data_available_through_height < self.bitcoin_checkpoint_height
            || [
                self.configuration_hash,
                self.bitcoin_checkpoint_hash,
                self.bitcoin_checkpoint_chainwork,
                self.truthcoin_genesis_hash,
                self.truthcoin_tip_hash,
                self.truthcoin_tip_parent_bitcoin_hash,
                self.canonical_path_root,
                self.replay_transcript_root,
                self.complete_state_root,
                self.decision_registry_root,
                self.market_registry_root,
                self.lmsr_state_root,
                self.sample_window_root,
                self.selected_anchor_commitment,
                self.selected_fast_market_commitment,
                self.oracle_certificate_commitment,
                self.cumulative_update_root,
            ]
            .contains(&[0; 32])
            || (self.sequence == 0 && self.last_update_proof_commitment != [0; 32])
            || (self.sequence != 0 && self.last_update_proof_commitment == [0; 32])
        {
            return Err(ProtocolError::InvalidTruthcoinAnchor);
        }
        Ok(())
    }

    pub fn commitment(&self) -> Hash32 {
        tagged_hash("ECX/truthcoin-anchor-state/v1", &self.canonical_bytes())
    }

    fn history_material(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_u8(&mut out, self.version);
        out.extend_from_slice(&self.configuration_hash);
        put_u64(&mut out, self.sequence);
        out.extend_from_slice(&self.bitcoin_checkpoint_hash);
        put_u64(&mut out, self.bitcoin_checkpoint_height);
        put_u64(&mut out, self.bitcoin_checkpoint_mtp);
        out.extend_from_slice(&self.bitcoin_checkpoint_chainwork);
        out.extend_from_slice(&self.truthcoin_genesis_hash);
        out.extend_from_slice(&self.truthcoin_tip_hash);
        put_u64(&mut out, self.truthcoin_tip_height);
        out.extend_from_slice(&self.truthcoin_tip_parent_bitcoin_hash);
        out.extend_from_slice(&self.canonical_path_root);
        out.extend_from_slice(&self.replay_transcript_root);
        out.extend_from_slice(&self.complete_state_root);
        out.extend_from_slice(&self.decision_registry_root);
        out.extend_from_slice(&self.market_registry_root);
        out.extend_from_slice(&self.lmsr_state_root);
        out.extend_from_slice(&self.sample_window_root);
        out.extend_from_slice(&self.selected_anchor_commitment);
        out.extend_from_slice(&self.selected_fast_market_commitment);
        out.extend_from_slice(&self.oracle_certificate_commitment);
        put_u64(&mut out, self.last_update_elements_height);
        put_u64(&mut out, self.source_data_available_through_height);
        out
    }
}

impl CanonicalEncode for TruthcoinAnchorStateV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.history_material());
        out.extend_from_slice(&self.cumulative_update_root);
        out.extend_from_slice(&self.last_update_proof_commitment);
    }
}

/// Public transaction linkage checked in addition to the recursive replay
/// proof. Output zero is the only permitted successor authority output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TruthcoinAnchorUpdateV1 {
    pub version: u8,
    pub prior_authority_outpoint: AnchorOutpointV1,
    pub successor_transaction_id: Hash32,
    pub successor_authority_output_index: u32,
    /// Commitment to the authenticated source-replay public values, BEFORE
    /// constructing the authority transaction. Never use the outer authority
    /// journal digest here: that journal includes the transaction ID and the
    /// successor script, whose state commits this field through the history
    /// root and `last_update_proof_commitment`. Doing so creates a hash cycle.
    /// The enclosing authority proof must bind both this source receipt and
    /// its separately constructed transaction journal.
    pub update_public_values_hash: Hash32,
}

impl TruthcoinAnchorUpdateV1 {
    pub const VERSION: u8 = 1;
}

impl CanonicalEncode for TruthcoinAnchorUpdateV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        self.prior_authority_outpoint.encode_to(out);
        out.extend_from_slice(&self.successor_transaction_id);
        put_u32(out, self.successor_authority_output_index);
        out.extend_from_slice(&self.update_public_values_hash);
    }
}

pub fn truthcoin_anchor_history_root(
    prior: &TruthcoinAnchorStateV1,
    successor: &TruthcoinAnchorStateV1,
    update: &TruthcoinAnchorUpdateV1,
) -> Hash32 {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&prior.cumulative_update_root);
    update.prior_authority_outpoint.encode_to(&mut bytes);
    bytes.extend_from_slice(&successor.history_material());
    bytes.extend_from_slice(&update.update_public_values_hash);
    tagged_hash("ECX/truthcoin-anchor-history/v1", &bytes)
}

/// Enforces the state-chain invariants outside the source replay proof.
pub fn verify_truthcoin_anchor_successor(
    prior: &TruthcoinAnchorStateV1,
    successor: &TruthcoinAnchorStateV1,
    update: &TruthcoinAnchorUpdateV1,
) -> Result<(), ProtocolError> {
    prior.validate()?;
    successor.validate()?;
    if update.version != TruthcoinAnchorUpdateV1::VERSION {
        return Err(ProtocolError::UnsupportedVersion);
    }
    if update.prior_authority_outpoint.txid == [0; 32]
        || update.successor_transaction_id == [0; 32]
        || update.update_public_values_hash == [0; 32]
        || update.successor_authority_output_index != 0
        || successor.sequence
            != prior
                .sequence
                .checked_add(1)
                .ok_or(ProtocolError::ArithmeticOverflow)?
        || successor.configuration_hash != prior.configuration_hash
        || successor.truthcoin_genesis_hash != prior.truthcoin_genesis_hash
        || successor.bitcoin_checkpoint_height <= prior.bitcoin_checkpoint_height
        || successor.bitcoin_checkpoint_mtp < prior.bitcoin_checkpoint_mtp
        || successor.bitcoin_checkpoint_chainwork <= prior.bitcoin_checkpoint_chainwork
        || successor.source_data_available_through_height
            < prior.source_data_available_through_height
        || successor.source_data_available_through_height < successor.bitcoin_checkpoint_height
        || successor.last_update_elements_height <= prior.last_update_elements_height
        || successor.last_update_proof_commitment != update.update_public_values_hash
        || successor.cumulative_update_root
            != truthcoin_anchor_history_root(prior, successor, update)
    {
        return Err(ProtocolError::InvalidTruthcoinAnchorSuccessor);
    }

    if successor.truthcoin_tip_height < prior.truthcoin_tip_height {
        return Err(ProtocolError::InvalidTruthcoinAnchorSuccessor);
    }
    if successor.truthcoin_tip_height == prior.truthcoin_tip_height {
        let unchanged = successor.truthcoin_tip_hash == prior.truthcoin_tip_hash
            && successor.truthcoin_tip_parent_bitcoin_hash
                == prior.truthcoin_tip_parent_bitcoin_hash
            && successor.replay_transcript_root == prior.replay_transcript_root
            && successor.complete_state_root == prior.complete_state_root
            && successor.decision_registry_root == prior.decision_registry_root
            && successor.market_registry_root == prior.market_registry_root
            && successor.lmsr_state_root == prior.lmsr_state_root
            && successor.sample_window_root == prior.sample_window_root
            && successor.selected_anchor_commitment == prior.selected_anchor_commitment
            && successor.selected_fast_market_commitment == prior.selected_fast_market_commitment
            && successor.oracle_certificate_commitment == prior.oracle_certificate_commitment;
        if !unchanged {
            return Err(ProtocolError::InvalidTruthcoinAnchorSuccessor);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(byte: u8) -> Hash32 {
        [byte; 32]
    }

    fn bootstrap() -> TruthcoinAnchorStateV1 {
        TruthcoinAnchorStateV1 {
            version: 1,
            configuration_hash: h(1),
            sequence: 0,
            bitcoin_checkpoint_hash: h(2),
            bitcoin_checkpoint_height: 100,
            bitcoin_checkpoint_mtp: 1_000,
            bitcoin_checkpoint_chainwork: h(3),
            truthcoin_genesis_hash: h(4),
            truthcoin_tip_hash: h(5),
            truthcoin_tip_height: 10,
            truthcoin_tip_parent_bitcoin_hash: h(6),
            canonical_path_root: h(7),
            replay_transcript_root: h(8),
            complete_state_root: h(9),
            decision_registry_root: h(10),
            market_registry_root: h(11),
            lmsr_state_root: h(12),
            sample_window_root: h(13),
            selected_anchor_commitment: h(14),
            selected_fast_market_commitment: h(15),
            oracle_certificate_commitment: h(16),
            last_update_elements_height: 50,
            source_data_available_through_height: 100,
            cumulative_update_root: h(17),
            last_update_proof_commitment: [0; 32],
        }
    }

    fn update() -> TruthcoinAnchorUpdateV1 {
        TruthcoinAnchorUpdateV1 {
            version: 1,
            prior_authority_outpoint: AnchorOutpointV1 {
                txid: h(30),
                vout: 0,
            },
            successor_transaction_id: h(31),
            successor_authority_output_index: 0,
            update_public_values_hash: h(32),
        }
    }

    fn heartbeat(
        prior: &TruthcoinAnchorStateV1,
        update: &TruthcoinAnchorUpdateV1,
    ) -> TruthcoinAnchorStateV1 {
        let mut next = prior.clone();
        next.sequence += 1;
        next.bitcoin_checkpoint_hash = h(40);
        next.bitcoin_checkpoint_height += 1;
        next.bitcoin_checkpoint_mtp += 60;
        next.bitcoin_checkpoint_chainwork = h(41);
        next.canonical_path_root = h(42);
        next.last_update_elements_height += 1;
        next.source_data_available_through_height += 1;
        next.last_update_proof_commitment = update.update_public_values_hash;
        next.cumulative_update_root = truthcoin_anchor_history_root(prior, &next, update);
        next
    }

    #[test]
    fn accepts_authenticated_heartbeat_without_refreshing_oracle() {
        let prior = bootstrap();
        let update = update();
        let next = heartbeat(&prior, &update);
        verify_truthcoin_anchor_successor(&prior, &next, &update).unwrap();
        assert_eq!(
            next.oracle_certificate_commitment,
            prior.oracle_certificate_commitment
        );
    }

    #[test]
    fn accepts_truthcoin_advance() {
        let prior = bootstrap();
        let update = update();
        let mut next = heartbeat(&prior, &update);
        next.truthcoin_tip_height += 1;
        next.truthcoin_tip_hash = h(50);
        next.truthcoin_tip_parent_bitcoin_hash = next.bitcoin_checkpoint_hash;
        next.replay_transcript_root = h(51);
        next.complete_state_root = h(52);
        next.market_registry_root = h(53);
        next.lmsr_state_root = h(54);
        next.sample_window_root = h(55);
        next.selected_fast_market_commitment = h(56);
        next.oracle_certificate_commitment = h(57);
        next.cumulative_update_root = truthcoin_anchor_history_root(&prior, &next, &update);
        verify_truthcoin_anchor_successor(&prior, &next, &update).unwrap();
    }

    #[test]
    fn rejects_heartbeat_that_refreshes_price() {
        let prior = bootstrap();
        let update = update();
        let mut next = heartbeat(&prior, &update);
        next.oracle_certificate_commitment = h(60);
        next.cumulative_update_root = truthcoin_anchor_history_root(&prior, &next, &update);
        assert_eq!(
            verify_truthcoin_anchor_successor(&prior, &next, &update),
            Err(ProtocolError::InvalidTruthcoinAnchorSuccessor)
        );
    }

    #[test]
    fn rejects_skipped_sequence_and_history_splice() {
        let prior = bootstrap();
        let update = update();
        let mut next = heartbeat(&prior, &update);
        next.sequence += 1;
        assert_eq!(
            verify_truthcoin_anchor_successor(&prior, &next, &update),
            Err(ProtocolError::InvalidTruthcoinAnchorSuccessor)
        );
        let mut next = heartbeat(&prior, &update);
        next.cumulative_update_root = h(99);
        assert_eq!(
            verify_truthcoin_anchor_successor(&prior, &next, &update),
            Err(ProtocolError::InvalidTruthcoinAnchorSuccessor)
        );
    }
}
