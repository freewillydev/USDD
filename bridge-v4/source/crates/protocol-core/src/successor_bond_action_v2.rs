//! Lifetime-safe signed insurance-bond actions for the incremental successor.
//!
//! The finite V18 action formats remain unchanged. These formats use fresh
//! domains and direct `u128` account/queue counters so a successor proof never
//! narrows a reachable replay identity into the historical `u64` wire.

use secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};

use crate::availability::AvailabilityConfigV1;
use crate::bond_inbox_v2::{BondInboxActionKindV2, BOND_INBOX_MARKER_LEN, BOND_INBOX_MARKER_MAGIC};
use crate::codec::{put_u128, put_u32, put_u64, put_u8, CanonicalEncode, Decoder};
use crate::hash::{canonical_hash, tagged_hash, Hash32};
use crate::order::Signature64;
use crate::types::XOnlyKey;
use crate::{ProtocolError, SuccessorRedemptionQueueEntryV2};

pub const SUCCESSOR_BOND_SUBSCRIPTION_ENCODED_LEN_V2: usize = 225;
pub const SUCCESSOR_SIGNED_BOND_SUBSCRIPTION_ENCODED_LEN_V2: usize = 289;
pub const SUCCESSOR_RECAPITALIZATION_ENCODED_LEN_V2: usize = 193;
pub const SUCCESSOR_SIGNED_RECAPITALIZATION_ENCODED_LEN_V2: usize = 257;
pub const SUCCESSOR_REDEMPTION_ENQUEUE_ENCODED_LEN_V2: usize = 321;
pub const SUCCESSOR_SIGNED_REDEMPTION_ENQUEUE_ENCODED_LEN_V2: usize = 385;
pub const SUCCESSOR_REDEMPTION_CANCELLATION_ENCODED_LEN_V2: usize = 241;
pub const SUCCESSOR_SIGNED_REDEMPTION_CANCELLATION_ENCODED_LEN_V2: usize = 305;
pub const SUCCESSOR_BOND_INBOX_MARKER_VERSION_V2: u8 = 3;

fn nonzero(value: Hash32) -> Result<(), ProtocolError> {
    if value == [0; 32] {
        Err(ProtocolError::InvalidBondState)
    } else {
        Ok(())
    }
}

fn signer_key(key: &SecretKey) -> XOnlyKey {
    let keypair = Keypair::from_secret_key(&Secp256k1::new(), key);
    XOnlyKey(XOnlyPublicKey::from_keypair(&keypair).0.serialize())
}

fn sign(signer: XOnlyKey, key: &SecretKey, digest: Hash32) -> Result<Signature64, ProtocolError> {
    if signer_key(key) != signer {
        return Err(ProtocolError::SigningKeyMismatch);
    }
    let message =
        Message::from_digest_slice(&digest).map_err(|_| ProtocolError::InvalidSignature)?;
    let keypair = Keypair::from_secret_key(&Secp256k1::new(), key);
    Ok(Signature64(
        *Secp256k1::new()
            .sign_schnorr_no_aux_rand(&message, &keypair)
            .as_ref(),
    ))
}

fn verify(signer: XOnlyKey, signature: Signature64, digest: Hash32) -> Result<(), ProtocolError> {
    let public =
        XOnlyPublicKey::from_slice(&signer.0).map_err(|_| ProtocolError::InvalidSignature)?;
    let signature = secp256k1::schnorr::Signature::from_slice(&signature.0)
        .map_err(|_| ProtocolError::InvalidSignature)?;
    let message =
        Message::from_digest_slice(&digest).map_err(|_| ProtocolError::InvalidSignature)?;
    Secp256k1::verification_only()
        .verify_schnorr(&signature, &message, &public)
        .map_err(|_| ProtocolError::InvalidSignature)
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorBondSubscriptionV2 {
    pub version: u8,
    pub chain_id: Hash32,
    pub configuration_hash: Hash32,
    pub trader: XOnlyKey,
    pub account_nonce: u128,
    pub contribution_usdd_atoms: u64,
    pub issued_share_atoms: u64,
    pub bond_recipient_script_sha256: Hash32,
    pub usdd_output_opening_commitment: Hash32,
    pub bond_output_opening_commitment: Hash32,
}

impl SuccessorBondSubscriptionV2 {
    pub const VERSION: u8 = 2;

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION
            || self.chain_id == [0; 32]
            || self.configuration_hash == [0; 32]
            || self.contribution_usdd_atoms == 0
            || self.issued_share_atoms == 0
        {
            return Err(ProtocolError::InvalidBondState);
        }
        nonzero(self.bond_recipient_script_sha256)?;
        nonzero(self.usdd_output_opening_commitment)?;
        nonzero(self.bond_output_opening_commitment)
    }

    pub fn subscription_id(&self) -> Hash32 {
        let mut bytes = Vec::with_capacity(193);
        bytes.push(self.version);
        bytes.extend_from_slice(&self.chain_id);
        bytes.extend_from_slice(&self.configuration_hash);
        bytes.extend_from_slice(&self.trader.0);
        bytes.extend_from_slice(&self.account_nonce.to_be_bytes());
        bytes.extend_from_slice(&self.contribution_usdd_atoms.to_be_bytes());
        bytes.extend_from_slice(&self.issued_share_atoms.to_be_bytes());
        bytes.extend_from_slice(&self.bond_recipient_script_sha256);
        tagged_hash("ECX/successor-bond-subscription-id/v2-u128", &bytes)
    }

    pub fn action_id(&self) -> Hash32 {
        canonical_hash("ECX/successor-bond-subscription-action/v2-u128", self)
    }

    pub fn decode_fixed(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != SUCCESSOR_BOND_SUBSCRIPTION_ENCODED_LEN_V2 {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        let mut decoder = Decoder::new(bytes);
        let value = Self {
            version: decoder.u8()?,
            chain_id: decoder.take()?,
            configuration_hash: decoder.take()?,
            trader: XOnlyKey(decoder.take()?),
            account_nonce: u128::from_be_bytes(decoder.take()?),
            contribution_usdd_atoms: decoder.u64()?,
            issued_share_atoms: decoder.u64()?,
            bond_recipient_script_sha256: decoder.take()?,
            usdd_output_opening_commitment: decoder.take()?,
            bond_output_opening_commitment: decoder.take()?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }
}

impl CanonicalEncode for SuccessorBondSubscriptionV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(&self.configuration_hash);
        self.trader.encode_to(out);
        put_u128(out, self.account_nonce);
        put_u64(out, self.contribution_usdd_atoms);
        put_u64(out, self.issued_share_atoms);
        out.extend_from_slice(&self.bond_recipient_script_sha256);
        out.extend_from_slice(&self.usdd_output_opening_commitment);
        out.extend_from_slice(&self.bond_output_opening_commitment);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorSignedBondSubscriptionV2 {
    pub action: SuccessorBondSubscriptionV2,
    pub signature: Signature64,
}

impl SuccessorSignedBondSubscriptionV2 {
    pub fn sign(
        action: SuccessorBondSubscriptionV2,
        key: &SecretKey,
    ) -> Result<Self, ProtocolError> {
        action.validate()?;
        Ok(Self {
            signature: sign(action.trader, key, action.action_id())?,
            action,
        })
    }

    pub fn verify(&self) -> Result<(), ProtocolError> {
        self.action.validate()?;
        verify(self.action.trader, self.signature, self.action.action_id())
    }

    pub fn decode_fixed(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != SUCCESSOR_SIGNED_BOND_SUBSCRIPTION_ENCODED_LEN_V2 {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        let action = SuccessorBondSubscriptionV2::decode_fixed(
            &bytes[..SUCCESSOR_BOND_SUBSCRIPTION_ENCODED_LEN_V2],
        )?;
        let signature = Signature64(
            bytes[SUCCESSOR_BOND_SUBSCRIPTION_ENCODED_LEN_V2..]
                .try_into()
                .map_err(|_| ProtocolError::NonCanonicalEncoding)?,
        );
        Ok(Self { action, signature })
    }
}

impl CanonicalEncode for SuccessorSignedBondSubscriptionV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.action.encode_to(out);
        self.signature.encode_to(out);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorInsuranceRecapitalizationContributionV2 {
    pub version: u8,
    pub chain_id: Hash32,
    pub configuration_hash: Hash32,
    pub contributor: XOnlyKey,
    pub account_nonce: u128,
    pub contribution_usdd_atoms: u64,
    pub insurance_output_opening_commitment: Hash32,
    pub issued_share_atoms: u64,
    pub bond_output_opening_commitment: Hash32,
}

impl SuccessorInsuranceRecapitalizationContributionV2 {
    pub const VERSION: u8 = 2;
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION
            || self.chain_id == [0; 32]
            || self.configuration_hash == [0; 32]
            || self.contribution_usdd_atoms == 0
            || self.insurance_output_opening_commitment == [0; 32]
            || self.issued_share_atoms != 0
            || self.bond_output_opening_commitment != [0; 32]
        {
            return Err(ProtocolError::InvalidBondState);
        }
        Ok(())
    }
    pub fn contribution_id(&self) -> Hash32 {
        let mut bytes = Vec::with_capacity(129);
        bytes.push(self.version);
        bytes.extend_from_slice(&self.chain_id);
        bytes.extend_from_slice(&self.configuration_hash);
        bytes.extend_from_slice(&self.contributor.0);
        bytes.extend_from_slice(&self.account_nonce.to_be_bytes());
        bytes.extend_from_slice(&self.contribution_usdd_atoms.to_be_bytes());
        tagged_hash(
            "ECX/successor-insurance-recapitalization-id/v2-u128",
            &bytes,
        )
    }
    pub fn action_id(&self) -> Hash32 {
        canonical_hash(
            "ECX/successor-insurance-recapitalization-action/v2-u128",
            self,
        )
    }
    pub fn decode_fixed(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != SUCCESSOR_RECAPITALIZATION_ENCODED_LEN_V2 {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        let mut d = Decoder::new(bytes);
        let value = Self {
            version: d.u8()?,
            chain_id: d.take()?,
            configuration_hash: d.take()?,
            contributor: XOnlyKey(d.take()?),
            account_nonce: u128::from_be_bytes(d.take()?),
            contribution_usdd_atoms: d.u64()?,
            insurance_output_opening_commitment: d.take()?,
            issued_share_atoms: d.u64()?,
            bond_output_opening_commitment: d.take()?,
        };
        d.finish()?;
        value.validate()?;
        Ok(value)
    }
}

impl CanonicalEncode for SuccessorInsuranceRecapitalizationContributionV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(&self.configuration_hash);
        self.contributor.encode_to(out);
        put_u128(out, self.account_nonce);
        put_u64(out, self.contribution_usdd_atoms);
        out.extend_from_slice(&self.insurance_output_opening_commitment);
        put_u64(out, self.issued_share_atoms);
        out.extend_from_slice(&self.bond_output_opening_commitment);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorSignedInsuranceRecapitalizationContributionV2 {
    pub action: SuccessorInsuranceRecapitalizationContributionV2,
    pub signature: Signature64,
}
impl SuccessorSignedInsuranceRecapitalizationContributionV2 {
    pub fn sign(
        action: SuccessorInsuranceRecapitalizationContributionV2,
        key: &SecretKey,
    ) -> Result<Self, ProtocolError> {
        action.validate()?;
        Ok(Self {
            signature: sign(action.contributor, key, action.action_id())?,
            action,
        })
    }
    pub fn verify(&self) -> Result<(), ProtocolError> {
        self.action.validate()?;
        verify(
            self.action.contributor,
            self.signature,
            self.action.action_id(),
        )
    }
    pub fn decode_fixed(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != SUCCESSOR_SIGNED_RECAPITALIZATION_ENCODED_LEN_V2 {
            return Err(ProtocolError::NonCanonicalEncoding);
        };
        let action = SuccessorInsuranceRecapitalizationContributionV2::decode_fixed(
            &bytes[..SUCCESSOR_RECAPITALIZATION_ENCODED_LEN_V2],
        )?;
        Ok(Self {
            action,
            signature: Signature64(
                bytes[SUCCESSOR_RECAPITALIZATION_ENCODED_LEN_V2..]
                    .try_into()
                    .map_err(|_| ProtocolError::NonCanonicalEncoding)?,
            ),
        })
    }
}
impl CanonicalEncode for SuccessorSignedInsuranceRecapitalizationContributionV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.action.encode_to(out);
        self.signature.encode_to(out);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorRedemptionEnqueueV2 {
    pub version: u8,
    pub chain_id: Hash32,
    pub configuration_hash: Hash32,
    pub claimant: XOnlyKey,
    pub account_nonce: u128,
    pub requested_share_atoms: u64,
    pub destination_script_hash: Hash32,
    pub holder_script_sha256: Hash32,
    pub intent_salt: Hash32,
    pub refund_script_sha256: Hash32,
    pub refund_not_before_parent_height: u64,
    pub bond_input_opening_commitment: Hash32,
    pub queue_output_opening_commitment: Hash32,
}
impl SuccessorRedemptionEnqueueV2 {
    pub const VERSION: u8 = 2;
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION
            || self.chain_id == [0; 32]
            || self.configuration_hash == [0; 32]
            || self.requested_share_atoms == 0
            || self.intent_salt == [0; 32]
            || self.refund_not_before_parent_height == 0
        {
            return Err(ProtocolError::InvalidBondState);
        };
        for value in [
            self.destination_script_hash,
            self.holder_script_sha256,
            self.refund_script_sha256,
            self.bond_input_opening_commitment,
            self.queue_output_opening_commitment,
        ] {
            nonzero(value)?;
        }
        Ok(())
    }
    pub fn stable_intent_id(&self) -> Hash32 {
        let mut b = Vec::with_capacity(217);
        b.push(self.version);
        b.extend_from_slice(&self.chain_id);
        b.extend_from_slice(&self.configuration_hash);
        b.extend_from_slice(&self.claimant.0);
        b.extend_from_slice(&self.account_nonce.to_be_bytes());
        b.extend_from_slice(&self.requested_share_atoms.to_be_bytes());
        b.extend_from_slice(&self.destination_script_hash);
        b.extend_from_slice(&self.holder_script_sha256);
        b.extend_from_slice(&self.intent_salt);
        b.extend_from_slice(&self.refund_script_sha256);
        b.extend_from_slice(&self.refund_not_before_parent_height.to_be_bytes());
        tagged_hash("ECX/successor-redemption-enqueue-intent/v2-u128", &b)
    }
    pub fn request_id(
        &self,
        assigned_sequence: u128,
        inbox_entry_hash: Hash32,
        observed_parent_height: u64,
    ) -> Hash32 {
        let mut b = Vec::with_capacity(120);
        b.extend_from_slice(&self.stable_intent_id());
        b.extend_from_slice(&inbox_entry_hash);
        b.extend_from_slice(&assigned_sequence.to_be_bytes());
        b.extend_from_slice(&observed_parent_height.to_be_bytes());
        tagged_hash("ECX/successor-redemption-request-id/v2-u128", &b)
    }
    pub fn action_id(&self) -> Hash32 {
        canonical_hash("ECX/successor-redemption-enqueue-action/v2-u128", self)
    }
    pub fn claimant_commitment(&self) -> Hash32 {
        tagged_hash("ECX/bond-claimant/v2", &self.claimant.0)
    }
    pub fn queue_entry(
        &self,
        assigned_sequence: u128,
        inbox_entry_hash: Hash32,
        observed_parent_height: u64,
    ) -> Result<SuccessorRedemptionQueueEntryV2, ProtocolError> {
        self.validate()?;
        SuccessorRedemptionQueueEntryV2::new(
            assigned_sequence,
            self.request_id(assigned_sequence, inbox_entry_hash, observed_parent_height),
            self.claimant_commitment(),
            self.destination_script_hash,
            self.requested_share_atoms,
            observed_parent_height,
        )
    }
    pub fn decode_fixed(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != SUCCESSOR_REDEMPTION_ENQUEUE_ENCODED_LEN_V2 {
            return Err(ProtocolError::NonCanonicalEncoding);
        };
        let mut d = Decoder::new(bytes);
        let v = Self {
            version: d.u8()?,
            chain_id: d.take()?,
            configuration_hash: d.take()?,
            claimant: XOnlyKey(d.take()?),
            account_nonce: u128::from_be_bytes(d.take()?),
            requested_share_atoms: d.u64()?,
            destination_script_hash: d.take()?,
            holder_script_sha256: d.take()?,
            intent_salt: d.take()?,
            refund_script_sha256: d.take()?,
            refund_not_before_parent_height: d.u64()?,
            bond_input_opening_commitment: d.take()?,
            queue_output_opening_commitment: d.take()?,
        };
        d.finish()?;
        v.validate()?;
        Ok(v)
    }
}
impl CanonicalEncode for SuccessorRedemptionEnqueueV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(&self.configuration_hash);
        self.claimant.encode_to(out);
        put_u128(out, self.account_nonce);
        put_u64(out, self.requested_share_atoms);
        out.extend_from_slice(&self.destination_script_hash);
        out.extend_from_slice(&self.holder_script_sha256);
        out.extend_from_slice(&self.intent_salt);
        out.extend_from_slice(&self.refund_script_sha256);
        put_u64(out, self.refund_not_before_parent_height);
        out.extend_from_slice(&self.bond_input_opening_commitment);
        out.extend_from_slice(&self.queue_output_opening_commitment);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorSignedRedemptionEnqueueV2 {
    pub action: SuccessorRedemptionEnqueueV2,
    pub signature: Signature64,
}
impl SuccessorSignedRedemptionEnqueueV2 {
    pub fn sign(
        action: SuccessorRedemptionEnqueueV2,
        key: &SecretKey,
    ) -> Result<Self, ProtocolError> {
        action.validate()?;
        Ok(Self {
            signature: sign(action.claimant, key, action.action_id())?,
            action,
        })
    }
    pub fn verify(&self) -> Result<(), ProtocolError> {
        self.action.validate()?;
        verify(
            self.action.claimant,
            self.signature,
            self.action.action_id(),
        )
    }
    pub fn decode_fixed(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != SUCCESSOR_SIGNED_REDEMPTION_ENQUEUE_ENCODED_LEN_V2 {
            return Err(ProtocolError::NonCanonicalEncoding);
        };
        let action = SuccessorRedemptionEnqueueV2::decode_fixed(
            &bytes[..SUCCESSOR_REDEMPTION_ENQUEUE_ENCODED_LEN_V2],
        )?;
        Ok(Self {
            action,
            signature: Signature64(
                bytes[SUCCESSOR_REDEMPTION_ENQUEUE_ENCODED_LEN_V2..]
                    .try_into()
                    .map_err(|_| ProtocolError::NonCanonicalEncoding)?,
            ),
        })
    }
}
impl CanonicalEncode for SuccessorSignedRedemptionEnqueueV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.action.encode_to(out);
        self.signature.encode_to(out);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorRedemptionCancellationV2Action {
    pub version: u8,
    pub chain_id: Hash32,
    pub configuration_hash: Hash32,
    pub claimant: XOnlyKey,
    pub sequence: u128,
    pub request_id: Hash32,
    pub bond_recipient_script_sha256: Hash32,
    pub queue_input_opening_commitment: Hash32,
    pub bond_return_output_opening_commitment: Hash32,
}
impl SuccessorRedemptionCancellationV2Action {
    pub const VERSION: u8 = 2;
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION
            || self.chain_id == [0; 32]
            || self.configuration_hash == [0; 32]
            || self.request_id == [0; 32]
        {
            return Err(ProtocolError::InvalidBondState);
        };
        nonzero(self.bond_recipient_script_sha256)?;
        nonzero(self.queue_input_opening_commitment)?;
        nonzero(self.bond_return_output_opening_commitment)
    }
    pub fn cancellation_id(&self) -> Hash32 {
        let mut b = Vec::with_capacity(177);
        b.push(self.version);
        b.extend_from_slice(&self.chain_id);
        b.extend_from_slice(&self.configuration_hash);
        b.extend_from_slice(&self.claimant.0);
        b.extend_from_slice(&self.sequence.to_be_bytes());
        b.extend_from_slice(&self.request_id);
        b.extend_from_slice(&self.bond_recipient_script_sha256);
        tagged_hash("ECX/successor-redemption-cancellation-id/v2-u128", &b)
    }
    pub fn action_id(&self) -> Hash32 {
        canonical_hash("ECX/successor-redemption-cancellation-action/v2-u128", self)
    }
    pub fn decode_fixed(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != SUCCESSOR_REDEMPTION_CANCELLATION_ENCODED_LEN_V2 {
            return Err(ProtocolError::NonCanonicalEncoding);
        };
        let mut d = Decoder::new(bytes);
        let v = Self {
            version: d.u8()?,
            chain_id: d.take()?,
            configuration_hash: d.take()?,
            claimant: XOnlyKey(d.take()?),
            sequence: u128::from_be_bytes(d.take()?),
            request_id: d.take()?,
            bond_recipient_script_sha256: d.take()?,
            queue_input_opening_commitment: d.take()?,
            bond_return_output_opening_commitment: d.take()?,
        };
        d.finish()?;
        v.validate()?;
        Ok(v)
    }
}
impl CanonicalEncode for SuccessorRedemptionCancellationV2Action {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(&self.configuration_hash);
        self.claimant.encode_to(out);
        put_u128(out, self.sequence);
        out.extend_from_slice(&self.request_id);
        out.extend_from_slice(&self.bond_recipient_script_sha256);
        out.extend_from_slice(&self.queue_input_opening_commitment);
        out.extend_from_slice(&self.bond_return_output_opening_commitment);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorSignedRedemptionCancellationV2 {
    pub action: SuccessorRedemptionCancellationV2Action,
    pub signature: Signature64,
}
impl SuccessorSignedRedemptionCancellationV2 {
    pub fn sign(
        action: SuccessorRedemptionCancellationV2Action,
        key: &SecretKey,
    ) -> Result<Self, ProtocolError> {
        action.validate()?;
        Ok(Self {
            signature: sign(action.claimant, key, action.action_id())?,
            action,
        })
    }
    pub fn verify(&self) -> Result<(), ProtocolError> {
        self.action.validate()?;
        verify(
            self.action.claimant,
            self.signature,
            self.action.action_id(),
        )
    }
    pub fn decode_fixed(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != SUCCESSOR_SIGNED_REDEMPTION_CANCELLATION_ENCODED_LEN_V2 {
            return Err(ProtocolError::NonCanonicalEncoding);
        };
        let action = SuccessorRedemptionCancellationV2Action::decode_fixed(
            &bytes[..SUCCESSOR_REDEMPTION_CANCELLATION_ENCODED_LEN_V2],
        )?;
        Ok(Self {
            action,
            signature: Signature64(
                bytes[SUCCESSOR_REDEMPTION_CANCELLATION_ENCODED_LEN_V2..]
                    .try_into()
                    .map_err(|_| ProtocolError::NonCanonicalEncoding)?,
            ),
        })
    }
}
impl CanonicalEncode for SuccessorSignedRedemptionCancellationV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.action.encode_to(out);
        self.signature.encode_to(out);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SuccessorBondInboxUserActionV2 {
    Subscription(SuccessorSignedBondSubscriptionV2),
    InsuranceRecapitalizationContribution(SuccessorSignedInsuranceRecapitalizationContributionV2),
    RedemptionEnqueue(SuccessorSignedRedemptionEnqueueV2),
    RedemptionCancellation(SuccessorSignedRedemptionCancellationV2),
}
impl SuccessorBondInboxUserActionV2 {
    pub fn kind(&self) -> BondInboxActionKindV2 {
        match self {
            Self::Subscription(_) => BondInboxActionKindV2::Subscription,
            Self::InsuranceRecapitalizationContribution(_) => {
                BondInboxActionKindV2::InsuranceRecapitalizationContribution
            }
            Self::RedemptionEnqueue(_) => BondInboxActionKindV2::RedemptionEnqueue,
            Self::RedemptionCancellation(_) => BondInboxActionKindV2::RedemptionCancellation,
        }
    }
    pub fn signer(&self) -> XOnlyKey {
        match self {
            Self::Subscription(v) => v.action.trader,
            Self::InsuranceRecapitalizationContribution(v) => v.action.contributor,
            Self::RedemptionEnqueue(v) => v.action.claimant,
            Self::RedemptionCancellation(v) => v.action.claimant,
        }
    }
    pub fn action_id(&self) -> Hash32 {
        match self {
            Self::Subscription(v) => v.action.action_id(),
            Self::InsuranceRecapitalizationContribution(v) => v.action.action_id(),
            Self::RedemptionEnqueue(v) => v.action.action_id(),
            Self::RedemptionCancellation(v) => v.action.action_id(),
        }
    }
    pub fn staging_intent_id(&self) -> Hash32 {
        match self {
            Self::RedemptionEnqueue(v) => v.action.stable_intent_id(),
            _ => [0; 32],
        }
    }
    pub fn canonical_signed_bytes(&self) -> Vec<u8> {
        match self {
            Self::Subscription(v) => v.canonical_bytes(),
            Self::InsuranceRecapitalizationContribution(v) => v.canonical_bytes(),
            Self::RedemptionEnqueue(v) => v.canonical_bytes(),
            Self::RedemptionCancellation(v) => v.canonical_bytes(),
        }
    }
    pub fn canonical_signed_len(kind: BondInboxActionKindV2) -> usize {
        match kind {
            BondInboxActionKindV2::Subscription => {
                SUCCESSOR_SIGNED_BOND_SUBSCRIPTION_ENCODED_LEN_V2
            }
            BondInboxActionKindV2::InsuranceRecapitalizationContribution => {
                SUCCESSOR_SIGNED_RECAPITALIZATION_ENCODED_LEN_V2
            }
            BondInboxActionKindV2::RedemptionEnqueue => {
                SUCCESSOR_SIGNED_REDEMPTION_ENQUEUE_ENCODED_LEN_V2
            }
            BondInboxActionKindV2::RedemptionCancellation => {
                SUCCESSOR_SIGNED_REDEMPTION_CANCELLATION_ENCODED_LEN_V2
            }
        }
    }
    pub fn decode_fixed(kind: BondInboxActionKindV2, bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != Self::canonical_signed_len(kind) {
            return Err(ProtocolError::NonCanonicalEncoding);
        };
        Ok(match kind {
            BondInboxActionKindV2::Subscription => {
                Self::Subscription(SuccessorSignedBondSubscriptionV2::decode_fixed(bytes)?)
            }
            BondInboxActionKindV2::InsuranceRecapitalizationContribution => {
                Self::InsuranceRecapitalizationContribution(
                    SuccessorSignedInsuranceRecapitalizationContributionV2::decode_fixed(bytes)?,
                )
            }
            BondInboxActionKindV2::RedemptionEnqueue => {
                Self::RedemptionEnqueue(SuccessorSignedRedemptionEnqueueV2::decode_fixed(bytes)?)
            }
            BondInboxActionKindV2::RedemptionCancellation => Self::RedemptionCancellation(
                SuccessorSignedRedemptionCancellationV2::decode_fixed(bytes)?,
            ),
        })
    }
    pub fn verify(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Subscription(v) => v.verify(),
            Self::InsuranceRecapitalizationContribution(v) => v.verify(),
            Self::RedemptionEnqueue(v) => v.verify(),
            Self::RedemptionCancellation(v) => v.verify(),
        }
    }
    pub fn settlement_witness_commitment(&self) -> Hash32 {
        let mut b = Vec::with_capacity(96);
        b.extend_from_slice(&self.action_id());
        match self {
            Self::Subscription(v) => {
                b.extend_from_slice(&v.action.usdd_output_opening_commitment);
                b.extend_from_slice(&v.action.bond_output_opening_commitment)
            }
            Self::InsuranceRecapitalizationContribution(v) => {
                b.extend_from_slice(&v.action.insurance_output_opening_commitment);
                b.extend_from_slice(&v.action.bond_output_opening_commitment)
            }
            Self::RedemptionEnqueue(v) => {
                b.extend_from_slice(&v.action.bond_input_opening_commitment);
                b.extend_from_slice(&v.action.queue_output_opening_commitment)
            }
            Self::RedemptionCancellation(v) => {
                b.extend_from_slice(&v.action.queue_input_opening_commitment);
                b.extend_from_slice(&v.action.bond_return_output_opening_commitment)
            }
        }
        tagged_hash("ECX/successor-bond-settlement-witness/v2-u128", &b)
    }
}

fn decode_kind(value: u8) -> Result<BondInboxActionKindV2, ProtocolError> {
    match value {
        0 => Ok(BondInboxActionKindV2::Subscription),
        1 => Ok(BondInboxActionKindV2::RedemptionEnqueue),
        2 => Ok(BondInboxActionKindV2::RedemptionCancellation),
        3 => Ok(BondInboxActionKindV2::InsuranceRecapitalizationContribution),
        other => Err(ProtocolError::InvalidDiscriminant(other)),
    }
}

/// Amount-free successor marker. Its wire shape remains 503 bytes so node
/// extraction stays bounded, but version and signature/context domains are
/// fresh and its action ID names the u128 successor codec above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorBondInboxMarkerV2 {
    pub version: u8,
    pub kind: BondInboxActionKindV2,
    pub chain_id: Hash32,
    pub configuration_hash: Hash32,
    pub signer: XOnlyKey,
    pub action_id: Hash32,
    pub staging_intent_id: Hash32,
    pub staging_vout: u32,
    pub refund_script_sha256: Hash32,
    pub refund_not_before_parent_height: u64,
    pub payload_commitment: Hash32,
    pub availability_scheme_hash: Hash32,
    pub availability_custodian_registry_hash: Hash32,
    pub availability_bundle_root: Hash32,
    pub availability_context: Hash32,
    pub availability_receipt_root: Hash32,
    pub availability_bundle_len: u32,
    pub availability_receipt_bitmap: u8,
    pub source_authorization_commitment: Hash32,
    pub signature: Signature64,
}

impl SuccessorBondInboxMarkerV2 {
    pub const VERSION: u8 = SUCCESSOR_BOND_INBOX_MARKER_VERSION_V2;

    fn signing_digest(&self) -> Hash32 {
        let mut bytes = Vec::with_capacity(BOND_INBOX_MARKER_LEN - 4 - 64);
        put_u8(&mut bytes, self.version);
        self.kind.encode_to(&mut bytes);
        bytes.extend_from_slice(&self.chain_id);
        bytes.extend_from_slice(&self.configuration_hash);
        self.signer.encode_to(&mut bytes);
        bytes.extend_from_slice(&self.action_id);
        bytes.extend_from_slice(&self.staging_intent_id);
        put_u32(&mut bytes, self.staging_vout);
        bytes.extend_from_slice(&self.refund_script_sha256);
        put_u64(&mut bytes, self.refund_not_before_parent_height);
        bytes.extend_from_slice(&self.payload_commitment);
        bytes.extend_from_slice(&self.availability_scheme_hash);
        bytes.extend_from_slice(&self.availability_custodian_registry_hash);
        bytes.extend_from_slice(&self.availability_bundle_root);
        bytes.extend_from_slice(&self.availability_context);
        bytes.extend_from_slice(&self.availability_receipt_root);
        put_u32(&mut bytes, self.availability_bundle_len);
        put_u8(&mut bytes, self.availability_receipt_bitmap);
        bytes.extend_from_slice(&self.source_authorization_commitment);
        tagged_hash("ECX/successor-bond-inbox-marker-signature/v2-u128", &bytes)
    }

    pub fn expected_availability_context(&self) -> Hash32 {
        let mut bytes = Vec::with_capacity((32 * 7) + 12);
        bytes.extend_from_slice(&self.chain_id);
        bytes.extend_from_slice(&self.configuration_hash);
        bytes.extend_from_slice(&self.action_id);
        bytes.extend_from_slice(&self.staging_intent_id);
        put_u32(&mut bytes, self.staging_vout);
        bytes.extend_from_slice(&self.refund_script_sha256);
        put_u64(&mut bytes, self.refund_not_before_parent_height);
        bytes.extend_from_slice(&self.payload_commitment);
        bytes.extend_from_slice(&self.source_authorization_commitment);
        tagged_hash(
            "ECX/successor-bond-inbox-availability-context/v2-u128",
            &bytes,
        )
    }

    pub fn sign(mut self, key: &SecretKey) -> Result<Self, ProtocolError> {
        self.signature = sign(self.signer, key, self.signing_digest())?;
        Ok(self)
    }

    pub fn verify_wrapper_signature(&self) -> Result<(), ProtocolError> {
        verify(self.signer, self.signature, self.signing_digest())
            .map_err(|_| ProtocolError::InvalidBondInbox)
    }

    pub fn validate_syntax(&self, maximum_bundle_len: u32) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION
            || self.chain_id == [0; 32]
            || self.configuration_hash == [0; 32]
            || self.action_id == [0; 32]
            || self.payload_commitment == [0; 32]
            || self.availability_scheme_hash == [0; 32]
            || self.availability_custodian_registry_hash == [0; 32]
            || self.availability_bundle_root == [0; 32]
            || self.availability_receipt_root == [0; 32]
            || self.source_authorization_commitment == [0; 32]
            || self.availability_bundle_len == 0
            || self.availability_bundle_len > maximum_bundle_len
            || self.availability_context != self.expected_availability_context()
        {
            return Err(ProtocolError::InvalidBondInbox);
        }
        let has_enqueue_staging = self.staging_vout != u32::MAX
            && self.staging_intent_id != [0; 32]
            && self.refund_script_sha256 != [0; 32]
            && self.refund_not_before_parent_height != 0;
        let has_no_staging = self.staging_vout == u32::MAX
            && self.staging_intent_id == [0; 32]
            && self.refund_script_sha256 == [0; 32]
            && self.refund_not_before_parent_height == 0;
        if match self.kind {
            BondInboxActionKindV2::RedemptionEnqueue => !has_enqueue_staging,
            _ => !has_no_staging,
        } {
            return Err(ProtocolError::InvalidBondInbox);
        }
        Ok(())
    }

    pub fn verify_availability_claim(
        &self,
        availability: AvailabilityConfigV1,
        maximum_bundle_len: u32,
    ) -> Result<(), ProtocolError> {
        availability.validate()?;
        self.validate_syntax(maximum_bundle_len)?;
        let valid_bitmap_mask = (1u8 << availability.custodian_count) - 1;
        if self.availability_scheme_hash != availability.scheme_hash
            || self.availability_custodian_registry_hash != availability.custodian_registry_hash
            || self.availability_receipt_bitmap & !valid_bitmap_mask != 0
            || self.availability_receipt_bitmap.count_ones()
                < u32::from(availability.recovery_threshold)
        {
            return Err(ProtocolError::InvalidBondInbox);
        }
        Ok(())
    }

    pub fn payload_bytes(&self, maximum_bundle_len: u32) -> Result<Vec<u8>, ProtocolError> {
        self.validate_syntax(maximum_bundle_len)?;
        let mut out = Vec::with_capacity(BOND_INBOX_MARKER_LEN);
        out.extend_from_slice(&BOND_INBOX_MARKER_MAGIC);
        self.encode_to(&mut out);
        debug_assert_eq!(out.len(), BOND_INBOX_MARKER_LEN);
        Ok(out)
    }

    pub fn decode_payload(payload: &[u8], maximum_bundle_len: u32) -> Result<Self, ProtocolError> {
        if payload.len() != BOND_INBOX_MARKER_LEN {
            return Err(ProtocolError::InvalidBondInbox);
        }
        let mut decoder = Decoder::new(payload);
        if decoder.take::<4>()? != BOND_INBOX_MARKER_MAGIC {
            return Err(ProtocolError::InvalidBondInbox);
        }
        let marker = Self {
            version: decoder.u8()?,
            kind: decode_kind(decoder.u8()?)?,
            chain_id: decoder.take()?,
            configuration_hash: decoder.take()?,
            signer: XOnlyKey(decoder.take()?),
            action_id: decoder.take()?,
            staging_intent_id: decoder.take()?,
            staging_vout: decoder.u32()?,
            refund_script_sha256: decoder.take()?,
            refund_not_before_parent_height: decoder.u64()?,
            payload_commitment: decoder.take()?,
            availability_scheme_hash: decoder.take()?,
            availability_custodian_registry_hash: decoder.take()?,
            availability_bundle_root: decoder.take()?,
            availability_context: decoder.take()?,
            availability_receipt_root: decoder.take()?,
            availability_bundle_len: decoder.u32()?,
            availability_receipt_bitmap: decoder.u8()?,
            source_authorization_commitment: decoder.take()?,
            signature: Signature64(decoder.take()?),
        };
        decoder.finish()?;
        marker.validate_syntax(maximum_bundle_len)?;
        Ok(marker)
    }
}

impl CanonicalEncode for SuccessorBondInboxMarkerV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        self.kind.encode_to(out);
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(&self.configuration_hash);
        self.signer.encode_to(out);
        out.extend_from_slice(&self.action_id);
        out.extend_from_slice(&self.staging_intent_id);
        put_u32(out, self.staging_vout);
        out.extend_from_slice(&self.refund_script_sha256);
        put_u64(out, self.refund_not_before_parent_height);
        out.extend_from_slice(&self.payload_commitment);
        out.extend_from_slice(&self.availability_scheme_hash);
        out.extend_from_slice(&self.availability_custodian_registry_hash);
        out.extend_from_slice(&self.availability_bundle_root);
        out.extend_from_slice(&self.availability_context);
        out.extend_from_slice(&self.availability_receipt_root);
        put_u32(out, self.availability_bundle_len);
        put_u8(out, self.availability_receipt_bitmap);
        out.extend_from_slice(&self.source_authorization_commitment);
        self.signature.encode_to(out);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuccessorBondInboxAvailablePayloadV2 {
    pub commitment_blinding: Hash32,
    pub canonical_signed_action: Vec<u8>,
    pub settlement_witness_commitment: Hash32,
    pub source_authorization_commitment: Hash32,
}

impl SuccessorBondInboxAvailablePayloadV2 {
    pub fn commitment(
        kind: BondInboxActionKindV2,
        commitment_blinding: Hash32,
        canonical_signed_action: &[u8],
        settlement_witness_commitment: Hash32,
        source_authorization_commitment: Hash32,
    ) -> Hash32 {
        let mut bytes = Vec::with_capacity(97 + canonical_signed_action.len());
        bytes.extend_from_slice(&commitment_blinding);
        put_u8(&mut bytes, kind as u8);
        bytes.extend_from_slice(canonical_signed_action);
        bytes.extend_from_slice(&settlement_witness_commitment);
        bytes.extend_from_slice(&source_authorization_commitment);
        tagged_hash(
            "ECX/successor-bond-inbox-payload-commitment/v2-u128",
            &bytes,
        )
    }

    pub fn decode_canonical(
        kind: BondInboxActionKindV2,
        canonical_payload: &[u8],
    ) -> Result<Self, ProtocolError> {
        let signed_len = SuccessorBondInboxUserActionV2::canonical_signed_len(kind);
        let expected_len = 32usize
            .checked_add(4)
            .and_then(|value| value.checked_add(signed_len))
            .and_then(|value| value.checked_add(64))
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        if canonical_payload.len() != expected_len {
            return Err(ProtocolError::InvalidBondInbox);
        }
        let mut decoder = Decoder::new(canonical_payload);
        let commitment_blinding = decoder.take()?;
        if decoder.u32()? as usize != signed_len {
            return Err(ProtocolError::InvalidBondInbox);
        }
        let canonical_signed_action = match kind {
            BondInboxActionKindV2::Subscription => decoder.take::<289>()?.to_vec(),
            BondInboxActionKindV2::InsuranceRecapitalizationContribution => {
                decoder.take::<257>()?.to_vec()
            }
            BondInboxActionKindV2::RedemptionEnqueue => decoder.take::<385>()?.to_vec(),
            BondInboxActionKindV2::RedemptionCancellation => decoder.take::<305>()?.to_vec(),
        };
        let settlement_witness_commitment = decoder.take()?;
        let source_authorization_commitment = decoder.take()?;
        decoder.finish()?;
        Ok(Self {
            commitment_blinding,
            canonical_signed_action,
            settlement_witness_commitment,
            source_authorization_commitment,
        })
    }

    pub fn decode_action(
        &self,
        kind: BondInboxActionKindV2,
    ) -> Result<SuccessorBondInboxUserActionV2, ProtocolError> {
        SuccessorBondInboxUserActionV2::decode_fixed(kind, &self.canonical_signed_action)
    }
}

impl CanonicalEncode for SuccessorBondInboxAvailablePayloadV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.commitment_blinding);
        put_u32(
            out,
            u32::try_from(self.canonical_signed_action.len()).unwrap_or(u32::MAX),
        );
        out.extend_from_slice(&self.canonical_signed_action);
        out.extend_from_slice(&self.settlement_witness_commitment);
        out.extend_from_slice(&self.source_authorization_commitment);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key() -> SecretKey {
        SecretKey::from_slice(&[7; 32]).unwrap()
    }
    fn subscription(nonce: u128) -> SuccessorSignedBondSubscriptionV2 {
        let secret = key();
        SuccessorSignedBondSubscriptionV2::sign(
            SuccessorBondSubscriptionV2 {
                version: 2,
                chain_id: [1; 32],
                configuration_hash: [2; 32],
                trader: signer_key(&secret),
                account_nonce: nonce,
                contribution_usdd_atoms: 10,
                issued_share_atoms: 10,
                bond_recipient_script_sha256: [3; 32],
                usdd_output_opening_commitment: [4; 32],
                bond_output_opening_commitment: [5; 32],
            },
            &secret,
        )
        .unwrap()
    }
    #[test]
    fn successor_bond_actions_bind_high_u128_and_fixed_width() {
        let nonce = (1u128 << 96) + 9;
        let signed = subscription(nonce);
        signed.verify().unwrap();
        let bytes = signed.canonical_bytes();
        assert_eq!(
            bytes.len(),
            SUCCESSOR_SIGNED_BOND_SUBSCRIPTION_ENCODED_LEN_V2
        );
        assert_eq!(
            SuccessorSignedBondSubscriptionV2::decode_fixed(&bytes).unwrap(),
            signed
        );
        let mut mutated = bytes.clone();
        mutated[97] ^= 1;
        let changed = SuccessorSignedBondSubscriptionV2::decode_fixed(&mutated).unwrap();
        assert_ne!(changed.action.account_nonce, nonce);
        assert!(changed.verify().is_err());
        let action = SuccessorBondInboxUserActionV2::Subscription(signed);
        assert_eq!(
            SuccessorBondInboxUserActionV2::decode_fixed(
                action.kind(),
                &action.canonical_signed_bytes()
            )
            .unwrap(),
            action
        );
        let mut trailing = action.canonical_signed_bytes();
        trailing.push(0);
        assert!(SuccessorBondInboxUserActionV2::decode_fixed(action.kind(), &trailing).is_err());
    }
    #[test]
    fn every_successor_bond_action_length_is_fresh() {
        assert_eq!(SUCCESSOR_SIGNED_BOND_SUBSCRIPTION_ENCODED_LEN_V2, 281 + 8);
        assert_eq!(SUCCESSOR_SIGNED_RECAPITALIZATION_ENCODED_LEN_V2, 249 + 8);
        assert_eq!(SUCCESSOR_SIGNED_REDEMPTION_ENQUEUE_ENCODED_LEN_V2, 377 + 8);
        assert_eq!(
            SUCCESSOR_SIGNED_REDEMPTION_CANCELLATION_ENCODED_LEN_V2,
            297 + 8
        );
    }

    #[test]
    fn successor_marker_and_recovered_payload_are_exact_and_v18_separate() {
        let secret = key();
        let action = SuccessorBondInboxUserActionV2::Subscription(subscription((1u128 << 80) + 3));
        let signed_bytes = action.canonical_signed_bytes();
        let payload = SuccessorBondInboxAvailablePayloadV2 {
            commitment_blinding: [8; 32],
            canonical_signed_action: signed_bytes.clone(),
            settlement_witness_commitment: action.settlement_witness_commitment(),
            source_authorization_commitment: [9; 32],
        };
        let payload_commitment = SuccessorBondInboxAvailablePayloadV2::commitment(
            action.kind(),
            payload.commitment_blinding,
            &signed_bytes,
            payload.settlement_witness_commitment,
            payload.source_authorization_commitment,
        );
        let mut marker = SuccessorBondInboxMarkerV2 {
            version: SuccessorBondInboxMarkerV2::VERSION,
            kind: action.kind(),
            chain_id: [1; 32],
            configuration_hash: [2; 32],
            signer: action.signer(),
            action_id: action.action_id(),
            staging_intent_id: [0; 32],
            staging_vout: u32::MAX,
            refund_script_sha256: [0; 32],
            refund_not_before_parent_height: 0,
            payload_commitment,
            availability_scheme_hash: [10; 32],
            availability_custodian_registry_hash: [11; 32],
            availability_bundle_root: [12; 32],
            availability_context: [0; 32],
            availability_receipt_root: [13; 32],
            availability_bundle_len: 800,
            availability_receipt_bitmap: 0b00111,
            source_authorization_commitment: [9; 32],
            signature: Signature64([0; 64]),
        };
        marker.availability_context = marker.expected_availability_context();
        marker = marker.sign(&secret).unwrap();
        marker.verify_wrapper_signature().unwrap();
        let marker_bytes = marker.payload_bytes(1_000).unwrap();
        assert_eq!(marker_bytes.len(), BOND_INBOX_MARKER_LEN);
        assert_eq!(
            SuccessorBondInboxMarkerV2::decode_payload(&marker_bytes, 1_000).unwrap(),
            marker
        );
        assert_eq!(marker_bytes[4], SUCCESSOR_BOND_INBOX_MARKER_VERSION_V2);

        let payload_bytes = payload.canonical_bytes();
        let decoded =
            SuccessorBondInboxAvailablePayloadV2::decode_canonical(action.kind(), &payload_bytes)
                .unwrap();
        assert_eq!(decoded, payload);
        assert_eq!(decoded.decode_action(action.kind()).unwrap(), action);
        let mut trailing = payload_bytes;
        trailing.push(0);
        assert!(
            SuccessorBondInboxAvailablePayloadV2::decode_canonical(action.kind(), &trailing)
                .is_err()
        );
    }
}
