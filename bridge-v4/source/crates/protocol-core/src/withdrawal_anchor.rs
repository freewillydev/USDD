use crate::codec::{put_u32, put_u8, CanonicalEncode};
use crate::hash::{canonical_hash, Hash32};
use crate::ProtocolError;

pub const BMM_SLOT: u8 = 24;
pub const PXST_MARKER_MAGIC: [u8; 4] = *b"PXST";
pub const PXST_MARKER_LEN: usize = 4 + 1 + 32;
pub const PXST_OP_RETURN_SCRIPT_LEN: usize = 2 + PXST_MARKER_LEN;

/// Child-checkpoint fields authenticated by Elements consensus while building
/// the blinded withdrawal bundle. The parent miner later sees only the opaque
/// bundle hash and the BIP301 commitment to the resulting Elements header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuthenticatedChildCheckpointV1 {
    pub slot: u8,
    pub child_genesis_hash: Hash32,
    pub checkpoint_height: u32,
    pub previous_child_block_hash: Hash32,
    pub exchange_state_root: Hash32,
}

impl AuthenticatedChildCheckpointV1 {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.slot != BMM_SLOT {
            return Err(ProtocolError::WrongBmmSlot);
        }
        if self.child_genesis_hash == [0; 32]
            || self.checkpoint_height == 0
            || self.previous_child_block_hash == [0; 32]
            || self.exchange_state_root == [0; 32]
        {
            return Err(ProtocolError::InvalidWithdrawalStateAnchor);
        }
        Ok(())
    }
}

/// Cycle-free state authorization included in an additional M6 OP_RETURN output.
///
/// `existing_withdrawal_commitment` is the pre-existing `W_h`; callers must not
/// replace or reinterpret it. No current header hash, BMM critical hash, or m6id
/// appears here because each would create a hash dependency cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WithdrawalStateAnchorV1 {
    pub version: u8,
    pub slot: u8,
    pub child_genesis_hash: Hash32,
    /// Height encoded as `u32_be`, matching the branch's synthetic outpoint.
    pub checkpoint_height: u32,
    pub previous_child_block_hash: Hash32,
    pub existing_withdrawal_commitment: Hash32,
    pub exchange_state_root: Hash32,
}

impl WithdrawalStateAnchorV1 {
    pub const VERSION: u8 = 1;

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION {
            return Err(ProtocolError::UnsupportedVersion);
        }
        if self.slot != BMM_SLOT {
            return Err(ProtocolError::WrongBmmSlot);
        }
        if self.child_genesis_hash == [0; 32]
            || self.checkpoint_height == 0
            || self.previous_child_block_hash == [0; 32]
            || self.existing_withdrawal_commitment == [0; 32]
            || self.exchange_state_root == [0; 32]
        {
            return Err(ProtocolError::InvalidWithdrawalStateAnchor);
        }
        Ok(())
    }

    pub fn anchor_hash(&self) -> Result<Hash32, ProtocolError> {
        self.validate()?;
        Ok(canonical_hash("ECX/perps-m6-state/v1", self))
    }

    /// Returns `"PXST" || 0x01 || anchor_hash`, the exact M6 marker payload.
    pub fn marker_payload(&self) -> Result<[u8; PXST_MARKER_LEN], ProtocolError> {
        let mut payload = [0u8; PXST_MARKER_LEN];
        payload[..4].copy_from_slice(&PXST_MARKER_MAGIC);
        payload[4] = Self::VERSION;
        payload[5..].copy_from_slice(&self.anchor_hash()?);
        Ok(payload)
    }

    /// Minimal script encoding: `OP_RETURN PUSHBYTES_37 <PXST payload>`.
    pub fn op_return_script(&self) -> Result<[u8; PXST_OP_RETURN_SCRIPT_LEN], ProtocolError> {
        let mut script = [0u8; PXST_OP_RETURN_SCRIPT_LEN];
        script[0] = 0x6a;
        script[1] = PXST_MARKER_LEN as u8;
        script[2..].copy_from_slice(&self.marker_payload()?);
        Ok(script)
    }

    pub fn parse_marker_payload(payload: &[u8]) -> Result<Hash32, ProtocolError> {
        if payload.len() != PXST_MARKER_LEN
            || payload[..4] != PXST_MARKER_MAGIC
            || payload[4] != Self::VERSION
        {
            return Err(ProtocolError::MalformedPxstMarker);
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[5..]);
        Ok(hash)
    }
}

/// Verify, on the Elements side, that a blinded M6 commits to the exact child
/// state checkpoint. Outputs 0 through 2 must already have passed the existing
/// child withdrawal-bundle policy. The miner does not execute this function.
pub fn verify_child_withdrawal_state_commitment(
    checkpoint: &AuthenticatedChildCheckpointV1,
    existing_withdrawal_commitment: Hash32,
    m6_output_scripts: &[Vec<u8>],
) -> Result<(), ProtocolError> {
    checkpoint.validate()?;
    if existing_withdrawal_commitment == [0; 32] {
        return Err(ProtocolError::InvalidWithdrawalStateAnchor);
    }
    if m6_output_scripts.len() != 4 {
        return Err(ProtocolError::WithdrawalStateApprovalMismatch);
    }

    // A namespaced marker in any legacy position is an ordering/duplication
    // error. Outputs 0..=2 themselves remain interpreted by the existing M6
    // policy; this function only adds the fourth-output requirement.
    if m6_output_scripts[..3]
        .iter()
        .any(|script| script_is_pxst_namespaced(script))
    {
        return Err(ProtocolError::WithdrawalStateApprovalMismatch);
    }

    let expected = WithdrawalStateAnchorV1 {
        version: WithdrawalStateAnchorV1::VERSION,
        slot: checkpoint.slot,
        child_genesis_hash: checkpoint.child_genesis_hash,
        checkpoint_height: checkpoint.checkpoint_height,
        previous_child_block_hash: checkpoint.previous_child_block_hash,
        existing_withdrawal_commitment,
        exchange_state_root: checkpoint.exchange_state_root,
    }
    .op_return_script()?;
    if m6_output_scripts[3].as_slice() != expected {
        return Err(ProtocolError::WithdrawalStateApprovalMismatch);
    }
    Ok(())
}

fn script_is_pxst_namespaced(script: &[u8]) -> bool {
    script.len() >= 2 + PXST_MARKER_MAGIC.len()
        && script[0] == 0x6a
        && script[2..].starts_with(&PXST_MARKER_MAGIC)
}

impl CanonicalEncode for WithdrawalStateAnchorV1 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        put_u8(out, self.slot);
        out.extend_from_slice(&self.child_genesis_hash);
        put_u32(out, self.checkpoint_height);
        out.extend_from_slice(&self.previous_child_block_hash);
        out.extend_from_slice(&self.existing_withdrawal_commitment);
        out.extend_from_slice(&self.exchange_state_root);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor() -> WithdrawalStateAnchorV1 {
        WithdrawalStateAnchorV1 {
            version: 1,
            slot: 24,
            child_genesis_hash: [1; 32],
            checkpoint_height: 42,
            previous_child_block_hash: [2; 32],
            existing_withdrawal_commitment: [3; 32],
            exchange_state_root: [4; 32],
        }
    }

    #[test]
    fn marker_has_exact_consensus_shape() {
        let anchor = anchor();
        assert_eq!(anchor.canonical_bytes().len(), 134);
        let payload = anchor.marker_payload().unwrap();
        assert_eq!(payload.len(), 37);
        assert_eq!(&payload[..4], b"PXST");
        assert_eq!(payload[4], 1);
        assert_eq!(
            WithdrawalStateAnchorV1::parse_marker_payload(&payload).unwrap(),
            anchor.anchor_hash().unwrap()
        );
        let script = anchor.op_return_script().unwrap();
        assert_eq!(&script[..2], &[0x6a, 37]);
        assert_eq!(&script[2..], &payload);
    }

    #[test]
    fn every_authorization_field_is_bound() {
        let original = anchor();
        let expected = original.anchor_hash().unwrap();

        let mut variants = Vec::new();
        let mut value = original;
        value.child_genesis_hash[0] ^= 1;
        variants.push(value);
        let mut value = original;
        value.checkpoint_height += 1;
        variants.push(value);
        let mut value = original;
        value.previous_child_block_hash[0] ^= 1;
        variants.push(value);
        let mut value = original;
        value.existing_withdrawal_commitment[0] ^= 1;
        variants.push(value);
        let mut value = original;
        value.exchange_state_root[0] ^= 1;
        variants.push(value);

        for variant in variants {
            assert_ne!(variant.anchor_hash().unwrap(), expected);
        }
    }

    #[test]
    fn wrong_slot_fails_closed() {
        let mut wrong = anchor();
        wrong.slot = 25;
        assert_eq!(wrong.anchor_hash(), Err(ProtocolError::WrongBmmSlot));
    }

    #[test]
    fn matches_frozen_cpp_pxst_vector() {
        let fixture = WithdrawalStateAnchorV1 {
            version: 1,
            slot: 24,
            child_genesis_hash: [0x01; 32],
            checkpoint_height: 0x0102_0304,
            previous_child_block_hash: [0x02; 32],
            existing_withdrawal_commitment: [0x03; 32],
            exchange_state_root: [0x04; 32],
        };
        let anchor_hex: String = fixture
            .anchor_hash()
            .unwrap()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            anchor_hex,
            "21199ee28f8142f925e36f76d20e55db489c221cdf97ea5e67faec67b0e372c7"
        );
        let script_hex: String = fixture
            .op_return_script()
            .unwrap()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            script_hex,
            "6a25505853540121199ee28f8142f925e36f76d20e55db489c221cdf97ea5e67faec67b0e372c7"
        );
    }

    #[test]
    fn child_policy_requires_one_exact_fourth_output_from_authenticated_checkpoint() {
        let anchor = anchor();
        let checkpoint = AuthenticatedChildCheckpointV1 {
            slot: anchor.slot,
            child_genesis_hash: anchor.child_genesis_hash,
            checkpoint_height: anchor.checkpoint_height,
            previous_child_block_hash: anchor.previous_child_block_hash,
            exchange_state_root: anchor.exchange_state_root,
        };
        let legacy = vec![vec![0x6a, 0], vec![0x6a, 32], vec![0x51]];
        let mut outputs = legacy.clone();
        outputs.push(anchor.op_return_script().unwrap().to_vec());
        verify_child_withdrawal_state_commitment(
            &checkpoint,
            anchor.existing_withdrawal_commitment,
            &outputs,
        )
        .unwrap();

        let mut bad = outputs.clone();
        bad[3][38] ^= 1;
        assert_eq!(
            verify_child_withdrawal_state_commitment(
                &checkpoint,
                anchor.existing_withdrawal_commitment,
                &bad,
            ),
            Err(ProtocolError::WithdrawalStateApprovalMismatch)
        );

        let mut duplicate = outputs.clone();
        duplicate.insert(0, anchor.op_return_script().unwrap().to_vec());
        assert_eq!(
            verify_child_withdrawal_state_commitment(
                &checkpoint,
                anchor.existing_withdrawal_commitment,
                &duplicate,
            ),
            Err(ProtocolError::WithdrawalStateApprovalMismatch)
        );
    }

    #[test]
    fn child_policy_binds_every_authenticated_checkpoint_field() {
        let anchor = anchor();
        let checkpoint = AuthenticatedChildCheckpointV1 {
            slot: anchor.slot,
            child_genesis_hash: anchor.child_genesis_hash,
            checkpoint_height: anchor.checkpoint_height,
            previous_child_block_hash: anchor.previous_child_block_hash,
            exchange_state_root: anchor.exchange_state_root,
        };
        let outputs = vec![
            vec![0x6a, 0],
            vec![0x6a, 32],
            vec![0x51],
            anchor.op_return_script().unwrap().to_vec(),
        ];
        let mut variants = Vec::new();
        let mut value = checkpoint;
        value.child_genesis_hash[0] ^= 1;
        variants.push(value);
        let mut value = checkpoint;
        value.checkpoint_height += 1;
        variants.push(value);
        let mut value = checkpoint;
        value.previous_child_block_hash[0] ^= 1;
        variants.push(value);
        let mut value = checkpoint;
        value.exchange_state_root[0] ^= 1;
        variants.push(value);
        for value in variants {
            assert_eq!(
                verify_child_withdrawal_state_commitment(
                    &value,
                    anchor.existing_withdrawal_commitment,
                    &outputs,
                ),
                Err(ProtocolError::WithdrawalStateApprovalMismatch)
            );
        }

        let mut zero = checkpoint;
        zero.exchange_state_root = [0; 32];
        assert_eq!(
            zero.validate(),
            Err(ProtocolError::InvalidWithdrawalStateAnchor)
        );
    }
}
