//! Additive V2 transition verifier for the proof-enforced insurance bond.
//!
//! The V1 transition encoding and verifier remain unchanged. This module wraps
//! one complete V1 witness, replaces only its fee destination through a
//! crate-private hook, and verifies the additional bond, capital, signed-risk,
//! and deterministic-funding state committed by the V2 proof program.

use std::collections::{BTreeMap, BTreeSet};

use secp256k1::{schnorr, Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};

use crate::bond::{
    apply_subscription, capital_mode_for, coverage_bps, full_range_deficit,
    nav_per_whole_share_usdd_atoms, plan_fifo_redemption, plan_redemption_cancellation,
    target_reserve_125, BondPublicStateV2, CapitalModeV2, RedemptionCancellationV2,
    RedemptionQueueEntryV2, SubscriptionOutcomeV2,
};
use crate::bond_inbox_v2::{
    bond_inbox_outcome_genesis_root_v2, bond_inbox_outcome_next_root_v2,
    BondInboxConsumedDispositionV2, BondInboxConsumedOutcomeV2, BondInboxLimitsV2,
    BondInboxProcessedOutcomeV2, BondInboxRejectionV2, BondInboxTransitionV2,
    BondInboxUserActionV2,
};
use crate::codec::{put_u64, put_u8, CanonicalEncode};
use crate::configuration_v2::FrozenConfigurationV2;
use crate::execution_receipt_v2::{
    matcher_execution_receipt_batch_root_v2, verify_matcher_execution_batch_v2,
    MatcherExecutionReceiptV2, MatcherExecutionV2,
};
use crate::funding_v2::{
    advance_funding_timestamped_v2, TimestampedFundingObservationV2, FUNDING_EPOCH_SECONDS,
};
use crate::hash::{canonical_hash, tagged_hash, Hash32};
use crate::merkle::{ordered_root, KeyedCommitment, MerkleTree};
use crate::order::{OrderId, Signature64};
use crate::risk::{equity, notional, required_margin, MarginKind, RiskParams};
use crate::risk_v2::{creates_directional_risk, OrderRiskCommitmentV2};
use crate::state::{AccountLeaf, PositionLeaf};
use crate::state_v2::{ExchangeStateV2, PositionRiskLeafV2};
use crate::transition::{
    v2_accounts_before_external, verify_transition_v2_base, TransitionJournal, TransitionWitness,
    V2ExternalEffects,
};
use crate::types::{Amount, Position, Price, XOnlyKey};
use crate::ProtocolError;

pub const TRANSITION_PROTOCOL_VERSION_V2: u8 = 8;

fn verify_signature(
    signer: XOnlyKey,
    signature: Signature64,
    digest: Hash32,
) -> Result<(), ProtocolError> {
    let key = XOnlyPublicKey::from_slice(&signer.0).map_err(|_| ProtocolError::InvalidSignature)?;
    let signature = schnorr::Signature::from_slice(&signature.0)
        .map_err(|_| ProtocolError::InvalidSignature)?;
    let message =
        Message::from_digest_slice(&digest).map_err(|_| ProtocolError::InvalidSignature)?;
    Secp256k1::verification_only()
        .verify_schnorr(&signature, &message, &key)
        .map_err(|_| ProtocolError::InvalidSignature)
}

fn sign_digest(
    signer: XOnlyKey,
    secret_key: &SecretKey,
    digest: Hash32,
) -> Result<Signature64, ProtocolError> {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, secret_key);
    let (derived, _) = XOnlyPublicKey::from_keypair(&keypair);
    if signer.0 != derived.serialize() {
        return Err(ProtocolError::SigningKeyMismatch);
    }
    let message =
        Message::from_digest_slice(&digest).map_err(|_| ProtocolError::InvalidSignature)?;
    Ok(Signature64(
        *secp.sign_schnorr_no_aux_rand(&message, &keypair).as_ref(),
    ))
}

fn nonzero_commitment(value: Hash32) -> Result<(), ProtocolError> {
    if value == [0; 32] {
        Err(ProtocolError::InvalidBondState)
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BondSubscriptionV2 {
    pub version: u8,
    pub chain_id: Hash32,
    /// Frozen V2 singleton configuration. This prevents a valid signature
    /// from being replayed into another bond deployment on the same chain.
    pub configuration_hash: Hash32,
    pub trader: XOnlyKey,
    pub account_nonce: u64,
    pub contribution_usdd_atoms: u64,
    /// Exact result of the deterministic subscription NAV formula.
    pub issued_share_atoms: u64,
    pub bond_recipient_script_sha256: Hash32,
    /// Confidential USDD output opening, bound again by settlement_root.
    pub usdd_output_opening_commitment: Hash32,
    /// Confidential bond output opening and freely chosen holder script.
    pub bond_output_opening_commitment: Hash32,
}

impl BondSubscriptionV2 {
    pub const VERSION: u8 = 1;

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION
            || self.chain_id == [0; 32]
            || self.configuration_hash == [0; 32]
            || self.contribution_usdd_atoms == 0
            || self.issued_share_atoms == 0
        {
            return Err(ProtocolError::InvalidBondState);
        }
        nonzero_commitment(self.bond_recipient_script_sha256)?;
        nonzero_commitment(self.usdd_output_opening_commitment)?;
        nonzero_commitment(self.bond_output_opening_commitment)
    }

    /// Stable business identifier used by settlement roles. Opening hashes are
    /// deliberately excluded to avoid a circular id/opening construction.
    pub fn subscription_id(&self) -> Hash32 {
        let mut bytes = Vec::with_capacity(185);
        bytes.push(self.version);
        bytes.extend_from_slice(&self.chain_id);
        bytes.extend_from_slice(&self.configuration_hash);
        bytes.extend_from_slice(&self.trader.0);
        bytes.extend_from_slice(&self.account_nonce.to_be_bytes());
        bytes.extend_from_slice(&self.contribution_usdd_atoms.to_be_bytes());
        bytes.extend_from_slice(&self.issued_share_atoms.to_be_bytes());
        bytes.extend_from_slice(&self.bond_recipient_script_sha256);
        tagged_hash("ECX/bond-subscription-id/v2", &bytes)
    }

    /// Full signed action identifier, including exact settlement-opening
    /// hashes. This is distinct from [`Self::subscription_id`].
    pub fn action_id(&self) -> Hash32 {
        canonical_hash("ECX/bond-subscription-action/v2", self)
    }
}

impl CanonicalEncode for BondSubscriptionV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(&self.configuration_hash);
        self.trader.encode_to(out);
        put_u64(out, self.account_nonce);
        put_u64(out, self.contribution_usdd_atoms);
        put_u64(out, self.issued_share_atoms);
        out.extend_from_slice(&self.bond_recipient_script_sha256);
        out.extend_from_slice(&self.usdd_output_opening_commitment);
        out.extend_from_slice(&self.bond_output_opening_commitment);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SignedBondSubscriptionV2 {
    pub action: BondSubscriptionV2,
    pub signature: Signature64,
}

impl SignedBondSubscriptionV2 {
    pub fn sign(action: BondSubscriptionV2, key: &SecretKey) -> Result<Self, ProtocolError> {
        action.validate()?;
        Ok(Self {
            signature: sign_digest(action.trader, key, action.action_id())?,
            action,
        })
    }

    pub fn verify(&self) -> Result<(), ProtocolError> {
        self.action.validate()?;
        verify_signature(self.action.trader, self.signature, self.action.action_id())
    }
}

impl CanonicalEncode for SignedBondSubscriptionV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.action.encode_to(out);
        self.signature.encode_to(out);
    }
}

/// A non-dilutive insurance contribution used to recover a V2 singleton when
/// issuing ordinary bond shares is impossible or undesirable.  The action is
/// deliberately explicit about the absence of a bond output: both the issued
/// amount and the corresponding opening commitment must be zero.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct InsuranceRecapitalizationContributionV2 {
    pub version: u8,
    pub chain_id: Hash32,
    pub configuration_hash: Hash32,
    pub contributor: XOnlyKey,
    pub account_nonce: u64,
    pub contribution_usdd_atoms: u64,
    pub insurance_output_opening_commitment: Hash32,
    pub issued_share_atoms: u64,
    pub bond_output_opening_commitment: Hash32,
}

impl InsuranceRecapitalizationContributionV2 {
    pub const VERSION: u8 = 1;

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

    /// Stable settlement identifier excluding the confidential insurance
    /// opening, which may itself bind this identifier.
    pub fn contribution_id(&self) -> Hash32 {
        let mut bytes = Vec::with_capacity(121);
        bytes.push(self.version);
        bytes.extend_from_slice(&self.chain_id);
        bytes.extend_from_slice(&self.configuration_hash);
        bytes.extend_from_slice(&self.contributor.0);
        bytes.extend_from_slice(&self.account_nonce.to_be_bytes());
        bytes.extend_from_slice(&self.contribution_usdd_atoms.to_be_bytes());
        tagged_hash("ECX/insurance-recapitalization-contribution-id/v2", &bytes)
    }

    /// Complete signed intent, including the exact insurance output opening
    /// and the canonical zero-share/zero-bond-output assertion.
    pub fn action_id(&self) -> Hash32 {
        canonical_hash("ECX/insurance-recapitalization-contribution/v2", self)
    }
}

impl CanonicalEncode for InsuranceRecapitalizationContributionV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(&self.configuration_hash);
        self.contributor.encode_to(out);
        put_u64(out, self.account_nonce);
        put_u64(out, self.contribution_usdd_atoms);
        out.extend_from_slice(&self.insurance_output_opening_commitment);
        put_u64(out, self.issued_share_atoms);
        out.extend_from_slice(&self.bond_output_opening_commitment);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SignedInsuranceRecapitalizationContributionV2 {
    pub action: InsuranceRecapitalizationContributionV2,
    pub signature: Signature64,
}

impl SignedInsuranceRecapitalizationContributionV2 {
    pub fn sign(
        action: InsuranceRecapitalizationContributionV2,
        key: &SecretKey,
    ) -> Result<Self, ProtocolError> {
        action.validate()?;
        Ok(Self {
            signature: sign_digest(action.contributor, key, action.action_id())?,
            action,
        })
    }

    pub fn verify(&self) -> Result<(), ProtocolError> {
        self.action.validate()?;
        verify_signature(
            self.action.contributor,
            self.signature,
            self.action.action_id(),
        )
    }
}

impl CanonicalEncode for SignedInsuranceRecapitalizationContributionV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.action.encode_to(out);
        self.signature.encode_to(out);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RedemptionEnqueueV2 {
    pub version: u8,
    pub chain_id: Hash32,
    pub configuration_hash: Hash32,
    pub claimant: XOnlyKey,
    /// User-controlled anti-replay nonce. Queue sequence and inclusion height
    /// are assigned only after the action is consumed from the authenticated
    /// bond inbox and are intentionally absent from this signature.
    pub account_nonce: u64,
    pub requested_share_atoms: u64,
    pub destination_script_hash: Hash32,
    pub holder_script_sha256: Hash32,
    /// High-entropy user blinder for the public staging intent identifier.
    /// This prevents dictionary recovery of a small requested share amount.
    pub intent_salt: Hash32,
    /// Delayed holder-controlled escape branch of the source staging output.
    pub refund_script_sha256: Hash32,
    pub refund_not_before_parent_height: u64,
    pub bond_input_opening_commitment: Hash32,
    pub queue_output_opening_commitment: Hash32,
}

impl RedemptionEnqueueV2 {
    pub const VERSION: u8 = 1;

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION
            || self.chain_id == [0; 32]
            || self.configuration_hash == [0; 32]
            || self.requested_share_atoms == 0
            || self.intent_salt == [0; 32]
            || self.refund_not_before_parent_height == 0
        {
            return Err(ProtocolError::InvalidBondState);
        }
        nonzero_commitment(self.destination_script_hash)?;
        nonzero_commitment(self.holder_script_sha256)?;
        nonzero_commitment(self.refund_script_sha256)?;
        nonzero_commitment(self.bond_input_opening_commitment)?;
        nonzero_commitment(self.queue_output_opening_commitment)
    }

    /// Stable queued-request identifier excluding settlement-opening hashes.
    /// The full action signature still binds those hashes via
    /// [`Self::action_id`].
    pub fn request_id(
        &self,
        assigned_sequence: u64,
        inbox_entry_hash: Hash32,
        observed_parent_height: u64,
    ) -> Hash32 {
        let mut bytes = Vec::with_capacity(112);
        bytes.extend_from_slice(&self.stable_intent_id());
        bytes.extend_from_slice(&inbox_entry_hash);
        bytes.extend_from_slice(&assigned_sequence.to_be_bytes());
        bytes.extend_from_slice(&observed_parent_height.to_be_bytes());
        tagged_hash("ECX/redemption-request-id/v2", &bytes)
    }

    pub fn stable_intent_id(&self) -> Hash32 {
        let mut bytes = Vec::with_capacity(209);
        bytes.push(self.version);
        bytes.extend_from_slice(&self.chain_id);
        bytes.extend_from_slice(&self.configuration_hash);
        bytes.extend_from_slice(&self.claimant.0);
        bytes.extend_from_slice(&self.account_nonce.to_be_bytes());
        bytes.extend_from_slice(&self.requested_share_atoms.to_be_bytes());
        bytes.extend_from_slice(&self.destination_script_hash);
        bytes.extend_from_slice(&self.holder_script_sha256);
        bytes.extend_from_slice(&self.intent_salt);
        bytes.extend_from_slice(&self.refund_script_sha256);
        bytes.extend_from_slice(&self.refund_not_before_parent_height.to_be_bytes());
        tagged_hash("ECX/redemption-enqueue-stable-intent/v2", &bytes)
    }

    pub fn action_id(&self) -> Hash32 {
        canonical_hash("ECX/redemption-enqueue-action/v2", self)
    }

    pub fn claimant_commitment(&self) -> Hash32 {
        tagged_hash("ECX/bond-claimant/v2", &self.claimant.0)
    }

    pub fn queue_entry(
        &self,
        assigned_sequence: u64,
        inbox_entry_hash: Hash32,
        observed_parent_height: u64,
    ) -> Result<RedemptionQueueEntryV2, ProtocolError> {
        self.validate()?;
        RedemptionQueueEntryV2::new(
            assigned_sequence,
            self.request_id(assigned_sequence, inbox_entry_hash, observed_parent_height),
            self.claimant_commitment(),
            self.destination_script_hash,
            self.requested_share_atoms,
            observed_parent_height,
        )
    }
}

impl CanonicalEncode for RedemptionEnqueueV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(&self.configuration_hash);
        self.claimant.encode_to(out);
        put_u64(out, self.account_nonce);
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
pub struct SignedRedemptionEnqueueV2 {
    pub action: RedemptionEnqueueV2,
    pub signature: Signature64,
}

impl SignedRedemptionEnqueueV2 {
    pub fn sign(action: RedemptionEnqueueV2, key: &SecretKey) -> Result<Self, ProtocolError> {
        action.validate()?;
        Ok(Self {
            signature: sign_digest(action.claimant, key, action.action_id())?,
            action,
        })
    }

    pub fn verify(&self) -> Result<(), ProtocolError> {
        self.action.validate()?;
        verify_signature(
            self.action.claimant,
            self.signature,
            self.action.action_id(),
        )
    }
}

impl CanonicalEncode for SignedRedemptionEnqueueV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.action.encode_to(out);
        self.signature.encode_to(out);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RedemptionCancellationV2Action {
    pub version: u8,
    pub chain_id: Hash32,
    pub configuration_hash: Hash32,
    pub claimant: XOnlyKey,
    pub sequence: u64,
    pub request_id: Hash32,
    pub bond_recipient_script_sha256: Hash32,
    pub queue_input_opening_commitment: Hash32,
    pub bond_return_output_opening_commitment: Hash32,
}

impl RedemptionCancellationV2Action {
    pub const VERSION: u8 = 1;

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION
            || self.chain_id == [0; 32]
            || self.configuration_hash == [0; 32]
            || self.request_id == [0; 32]
        {
            return Err(ProtocolError::InvalidBondState);
        }
        nonzero_commitment(self.bond_recipient_script_sha256)?;
        nonzero_commitment(self.queue_input_opening_commitment)?;
        nonzero_commitment(self.bond_return_output_opening_commitment)
    }

    /// Stable settlement identifier. Exact opening commitments are excluded
    /// because the cancellation return opening contains this identifier; using
    /// the full signed action hash there would create an impossible hash/sign
    /// fixed point.
    pub fn cancellation_id(&self) -> Hash32 {
        let mut bytes = Vec::with_capacity(169);
        bytes.push(self.version);
        bytes.extend_from_slice(&self.chain_id);
        bytes.extend_from_slice(&self.configuration_hash);
        bytes.extend_from_slice(&self.claimant.0);
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.request_id);
        bytes.extend_from_slice(&self.bond_recipient_script_sha256);
        tagged_hash("ECX/redemption-cancellation-id/v2", &bytes)
    }

    /// Full signed action identifier, including the exact queue-input and
    /// holder-return opening commitments.
    pub fn action_id(&self) -> Hash32 {
        canonical_hash("ECX/redemption-cancellation/v2", self)
    }
}

impl CanonicalEncode for RedemptionCancellationV2Action {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(&self.configuration_hash);
        self.claimant.encode_to(out);
        put_u64(out, self.sequence);
        out.extend_from_slice(&self.request_id);
        out.extend_from_slice(&self.bond_recipient_script_sha256);
        out.extend_from_slice(&self.queue_input_opening_commitment);
        out.extend_from_slice(&self.bond_return_output_opening_commitment);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SignedRedemptionCancellationV2 {
    pub action: RedemptionCancellationV2Action,
    pub signature: Signature64,
}

impl SignedRedemptionCancellationV2 {
    pub fn sign(
        action: RedemptionCancellationV2Action,
        key: &SecretKey,
    ) -> Result<Self, ProtocolError> {
        action.validate()?;
        Ok(Self {
            signature: sign_digest(action.claimant, key, action.action_id())?,
            action,
        })
    }

    pub fn verify(&self) -> Result<(), ProtocolError> {
        self.action.validate()?;
        verify_signature(
            self.action.claimant,
            self.signature,
            self.action.action_id(),
        )
    }
}

impl CanonicalEncode for SignedRedemptionCancellationV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.action.encode_to(out);
        self.signature.encode_to(out);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RedemptionExecutionV2 {
    pub version: u8,
    pub sequence: u64,
    pub request_id: Hash32,
    pub redeemed_share_atoms: u64,
    pub paid_usdd_atoms: u128,
    pub queue_input_opening_commitment: Hash32,
    pub usdd_output_opening_commitment: Hash32,
    pub inventory_output_opening_commitment: Hash32,
    /// Exact confidential remainder queue output. Zero iff the FIFO entry is
    /// fully consumed; otherwise proof-core must authenticate this opening.
    pub queue_remainder_output_opening_commitment: Hash32,
}

impl RedemptionExecutionV2 {
    pub const VERSION: u8 = 1;

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != Self::VERSION
            || self.request_id == [0; 32]
            || self.redeemed_share_atoms == 0
            || self.paid_usdd_atoms == 0
        {
            return Err(ProtocolError::InvalidBondState);
        }
        nonzero_commitment(self.queue_input_opening_commitment)?;
        nonzero_commitment(self.usdd_output_opening_commitment)?;
        nonzero_commitment(self.inventory_output_opening_commitment)
    }

    pub fn action_id(&self) -> Hash32 {
        canonical_hash("ECX/redemption-execution/v2", self)
    }
}

impl CanonicalEncode for RedemptionExecutionV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        put_u64(out, self.sequence);
        out.extend_from_slice(&self.request_id);
        put_u64(out, self.redeemed_share_atoms);
        out.extend_from_slice(&self.paid_usdd_atoms.to_be_bytes());
        out.extend_from_slice(&self.queue_input_opening_commitment);
        out.extend_from_slice(&self.usdd_output_opening_commitment);
        out.extend_from_slice(&self.inventory_output_opening_commitment);
        out.extend_from_slice(&self.queue_remainder_output_opening_commitment);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TransitionPublicInputsV2 {
    pub protocol_version: u8,
    pub configuration_hash: Hash32,
    pub parent_mtp: u64,
    /// Inclusive freshness endpoint derived by the outer proof from the
    /// authenticated Truthcoin anchor/snapshot and frozen oracle ages. Funding
    /// never carries this quote beyond that endpoint.
    pub oracle_valid_through_mtp: u64,
    pub insurance_reserve_before_bond_actions: u128,
    pub authenticated_min_price: Price,
    pub authenticated_max_price: Price,
    pub authenticated_price_range_commitment: Hash32,
    pub previous_state_root: Hash32,
    pub next_state_root: Hash32,
    pub bond_action_root: Hash32,
    pub order_risk_root: Hash32,
    pub funding_state_root: Hash32,
    pub matcher_execution_receipt_batch_root: Hash32,
    pub previous_matcher_execution_sequence: u64,
    pub next_matcher_execution_sequence: u64,
    pub base_public_digest: Hash32,
}

impl TransitionPublicInputsV2 {
    pub const VERSION: u8 = TRANSITION_PROTOCOL_VERSION_V2;

    pub fn digest(&self) -> Hash32 {
        canonical_hash(
            "ECX/transition-public-inputs/v7-authenticated-funding-time-v2",
            self,
        )
    }
}

impl CanonicalEncode for TransitionPublicInputsV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.protocol_version);
        out.extend_from_slice(&self.configuration_hash);
        put_u64(out, self.parent_mtp);
        put_u64(out, self.oracle_valid_through_mtp);
        out.extend_from_slice(&self.insurance_reserve_before_bond_actions.to_be_bytes());
        self.authenticated_min_price.encode_to(out);
        self.authenticated_max_price.encode_to(out);
        out.extend_from_slice(&self.authenticated_price_range_commitment);
        out.extend_from_slice(&self.previous_state_root);
        out.extend_from_slice(&self.next_state_root);
        out.extend_from_slice(&self.bond_action_root);
        out.extend_from_slice(&self.order_risk_root);
        out.extend_from_slice(&self.funding_state_root);
        out.extend_from_slice(&self.matcher_execution_receipt_batch_root);
        put_u64(out, self.previous_matcher_execution_sequence);
        put_u64(out, self.next_matcher_execution_sequence);
        out.extend_from_slice(&self.base_public_digest);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TransitionWitnessV2 {
    pub public: TransitionPublicInputsV2,
    pub configuration: FrozenConfigurationV2,
    pub previous_state: ExchangeStateV2,
    pub next_state: ExchangeStateV2,
    pub bond_inbox: BondInboxTransitionV2,
    /// Derived accepted/rejected transcript, supplied for public-value and
    /// settlement binding and recomputed exactly by this verifier.
    pub bond_inbox_outcomes: Vec<BondInboxProcessedOutcomeV2>,
    pub base: TransitionWitness,
    /// Private proof witness. Exact quantities/order ids are never projected
    /// publicly; only the ordered batch root and cursors are public.
    pub matcher_execution_receipts: Vec<MatcherExecutionReceiptV2>,
    pub previous_redemption_queue: Vec<RedemptionQueueEntryV2>,
    pub next_redemption_queue: Vec<RedemptionQueueEntryV2>,
    pub subscriptions: Vec<SignedBondSubscriptionV2>,
    pub recapitalization_contributions: Vec<SignedInsuranceRecapitalizationContributionV2>,
    pub redemption_enqueues: Vec<SignedRedemptionEnqueueV2>,
    pub redemption_executions: Vec<RedemptionExecutionV2>,
    pub redemption_cancellations: Vec<SignedRedemptionCancellationV2>,
    pub order_risk_commitments: Vec<OrderRiskCommitmentV2>,
    pub previous_active_order_risk_commitments: Vec<OrderRiskCommitmentV2>,
    pub next_active_order_risk_commitments: Vec<OrderRiskCommitmentV2>,
    pub previous_position_risk: Vec<PositionRiskLeafV2>,
    pub next_position_risk: Vec<PositionRiskLeafV2>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TransitionJournalV2 {
    pub protocol_version: u8,
    pub configuration_hash: Hash32,
    pub parent_mtp: u64,
    pub oracle_valid_through_mtp: u64,
    pub authenticated_min_price: Price,
    pub authenticated_max_price: Price,
    pub authenticated_price_range_commitment: Hash32,
    pub previous_state_root: Hash32,
    pub next_state_root: Hash32,
    pub previous_sequence: u64,
    pub next_sequence: u64,
    pub bond_action_root: Hash32,
    pub order_risk_root: Hash32,
    pub funding_state_root: Hash32,
    pub matcher_execution_receipt_batch_root: Hash32,
    pub previous_matcher_execution_sequence: u64,
    pub next_matcher_execution_sequence: u64,
    pub capital_mode: CapitalModeV2,
    pub insurance_reserve: u128,
    pub outstanding_share_atoms: u64,
    pub inventory_share_atoms: u64,
    /// Zero only when no bond shares are outstanding.
    pub nav_per_whole_share_usdd_atoms: u128,
    pub full_bound_deficit: u128,
    pub target_reserve: u128,
    pub coverage_bps: u128,
    pub funding_epoch: u64,
    pub redemption_queue_root: Hash32,
    pub redemption_head: u64,
    pub redemption_tail: u64,
    pub queued_redemption_share_atoms: u64,
    pub bond_inbox_head_root: Hash32,
    pub bond_inbox_entry_count: u64,
    pub bond_inbox_processed_root: Hash32,
    pub bond_inbox_cursor: u64,
    pub bond_inbox_outcome_root: Hash32,
    pub bond_inbox_outcome_count: u64,
    pub base_journal_digest: Hash32,
}

impl TransitionJournalV2 {
    pub const VERSION: u8 = TRANSITION_PROTOCOL_VERSION_V2;

    pub fn digest(&self) -> Hash32 {
        canonical_hash("ECX/transition-journal/v9-expired-unavailable-v2", self)
    }
}

impl CanonicalEncode for TransitionJournalV2 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        put_u8(out, self.protocol_version);
        out.extend_from_slice(&self.configuration_hash);
        put_u64(out, self.parent_mtp);
        put_u64(out, self.oracle_valid_through_mtp);
        self.authenticated_min_price.encode_to(out);
        self.authenticated_max_price.encode_to(out);
        out.extend_from_slice(&self.authenticated_price_range_commitment);
        out.extend_from_slice(&self.previous_state_root);
        out.extend_from_slice(&self.next_state_root);
        put_u64(out, self.previous_sequence);
        put_u64(out, self.next_sequence);
        out.extend_from_slice(&self.bond_action_root);
        out.extend_from_slice(&self.order_risk_root);
        out.extend_from_slice(&self.funding_state_root);
        out.extend_from_slice(&self.matcher_execution_receipt_batch_root);
        put_u64(out, self.previous_matcher_execution_sequence);
        put_u64(out, self.next_matcher_execution_sequence);
        self.capital_mode.encode_to(out);
        out.extend_from_slice(&self.insurance_reserve.to_be_bytes());
        put_u64(out, self.outstanding_share_atoms);
        put_u64(out, self.inventory_share_atoms);
        out.extend_from_slice(&self.nav_per_whole_share_usdd_atoms.to_be_bytes());
        out.extend_from_slice(&self.full_bound_deficit.to_be_bytes());
        out.extend_from_slice(&self.target_reserve.to_be_bytes());
        out.extend_from_slice(&self.coverage_bps.to_be_bytes());
        put_u64(out, self.funding_epoch);
        out.extend_from_slice(&self.redemption_queue_root);
        put_u64(out, self.redemption_head);
        put_u64(out, self.redemption_tail);
        put_u64(out, self.queued_redemption_share_atoms);
        out.extend_from_slice(&self.bond_inbox_head_root);
        put_u64(out, self.bond_inbox_entry_count);
        out.extend_from_slice(&self.bond_inbox_processed_root);
        put_u64(out, self.bond_inbox_cursor);
        out.extend_from_slice(&self.bond_inbox_outcome_root);
        put_u64(out, self.bond_inbox_outcome_count);
        out.extend_from_slice(&self.base_journal_digest);
    }
}

pub fn redemption_queue_root_v2(entries: &[RedemptionQueueEntryV2]) -> Hash32 {
    ordered_root(
        "ECX/redemption-queue/v2",
        &entries
            .iter()
            .map(|entry| canonical_hash("ECX/redemption-entry/v2", entry))
            .collect::<Vec<_>>(),
    )
}

pub fn redemption_queue_has_capacity_v2(current_entries: usize, maximum_entries: u32) -> bool {
    maximum_entries != 0 && current_entries < maximum_entries as usize
}

pub fn order_risk_root_v2(commitments: &[OrderRiskCommitmentV2]) -> Hash32 {
    ordered_root(
        "ECX/order-risk-batch/v2",
        &commitments
            .iter()
            .map(|commitment| canonical_hash("ECX/order-risk-item/v2", commitment))
            .collect::<Vec<_>>(),
    )
}

pub fn active_order_risk_root_v2(
    commitments: &[OrderRiskCommitmentV2],
) -> Result<Hash32, ProtocolError> {
    Ok(MerkleTree::from_keyed(
        commitments
            .iter()
            .map(|commitment| KeyedCommitment {
                key: commitment.order_id,
                commitment: canonical_hash("ECX/active-order-risk/v2", commitment),
            })
            .collect(),
    )?
    .root())
}

pub fn position_risk_root_v2(leaves: &[PositionRiskLeafV2]) -> Result<Hash32, ProtocolError> {
    for leaf in leaves {
        leaf.validate()?;
    }
    Ok(MerkleTree::from_keyed(
        leaves
            .iter()
            .map(|leaf| KeyedCommitment {
                key: tagged_hash("ECX/position-risk-key/v2", &leaf.trader.0),
                commitment: leaf.commitment(),
            })
            .collect(),
    )?
    .root())
}

fn verify_persistent_risk_sets(witness: &TransitionWitnessV2) -> Result<(), ProtocolError> {
    fn active_map(
        commitments: &[OrderRiskCommitmentV2],
        params: RiskParams,
        configuration_hash: Hash32,
    ) -> Result<BTreeMap<OrderId, &OrderRiskCommitmentV2>, ProtocolError> {
        let mut map = BTreeMap::new();
        for commitment in commitments {
            commitment.verify(params)?;
            if commitment.configuration_hash != configuration_hash {
                return Err(ProtocolError::InvalidBondState);
            }
            if map.insert(commitment.order_id, commitment).is_some() {
                return Err(ProtocolError::DuplicateRequest);
            }
        }
        Ok(map)
    }
    let previous = active_map(
        &witness.previous_active_order_risk_commitments,
        witness.base.risk_params,
        witness.public.configuration_hash,
    )?;
    let next = active_map(
        &witness.next_active_order_risk_commitments,
        witness.base.risk_params,
        witness.public.configuration_hash,
    )?;
    if previous.len() != witness.base.previous_open_orders.len()
        || next.len() != witness.base.next_open_orders.len()
    {
        return Err(ProtocolError::InvalidBondState);
    }
    for order in &witness.base.previous_open_orders {
        let risk = previous
            .get(&order.order_id)
            .ok_or(ProtocolError::InvalidBondState)?;
        if risk.trader != order.trader {
            return Err(ProtocolError::InvalidSignature);
        }
    }
    let transition = witness
        .order_risk_commitments
        .iter()
        .map(|commitment| (commitment.order_id, commitment))
        .collect::<BTreeMap<_, _>>();
    // An order's selected margin is part of the economic terms accepted when
    // it enters the authenticated book. A second, valid trader signature for
    // the same canonical order id must not let a matcher/prover silently swap
    // that selection at fill time. Resting orders therefore retain the exact
    // commitment carried by the previous active-order root until cancellation.
    verify_resting_order_risk_immutability(&previous, &transition)?;
    for order in &witness.base.next_open_orders {
        let risk = next
            .get(&order.order_id)
            .ok_or(ProtocolError::InvalidBondState)?;
        let source = previous
            .get(&order.order_id)
            .copied()
            .or_else(|| transition.get(&order.order_id).copied());
        if risk.trader != order.trader || source != Some(*risk) {
            return Err(ProtocolError::InvalidBondState);
        }
    }

    fn position_map(
        leaves: &[PositionRiskLeafV2],
    ) -> Result<BTreeMap<[u8; 32], &PositionRiskLeafV2>, ProtocolError> {
        let mut map = BTreeMap::new();
        for leaf in leaves {
            leaf.validate()?;
            if map.insert(leaf.trader.0, leaf).is_some() {
                return Err(ProtocolError::DuplicateMerkleKey);
            }
        }
        Ok(map)
    }
    let previous_positions = position_map(&witness.previous_position_risk)?;
    let next_positions = position_map(&witness.next_position_risk)?;
    if previous_positions.len() != witness.base.previous_positions.len()
        || next_positions.len() != witness.base.next_positions.len()
    {
        return Err(ProtocolError::InvalidBondState);
    }
    for position in &witness.base.previous_positions {
        let risk = previous_positions
            .get(&position.trader.0)
            .ok_or(ProtocolError::InvalidBondState)?;
        if position.position.size == 0
            && risk.selected_initial_margin_bps != witness.base.risk_params.initial_margin_bps
        {
            return Err(ProtocolError::InvalidBondState);
        }
    }
    for position in &witness.base.next_positions {
        let risk = next_positions
            .get(&position.trader.0)
            .ok_or(ProtocolError::InvalidBondState)?;
        if position.position.size == 0
            && risk.selected_initial_margin_bps != witness.base.risk_params.initial_margin_bps
        {
            return Err(ProtocolError::InvalidBondState);
        }
    }
    Ok(())
}

fn verify_resting_order_risk_immutability(
    previous: &BTreeMap<OrderId, &OrderRiskCommitmentV2>,
    transition: &BTreeMap<OrderId, &OrderRiskCommitmentV2>,
) -> Result<(), ProtocolError> {
    for (order_id, commitment) in transition {
        if previous
            .get(order_id)
            .is_some_and(|previous_commitment| *previous_commitment != *commitment)
        {
            return Err(ProtocolError::InvalidBondState);
        }
    }
    Ok(())
}

pub fn bond_action_root_v2(witness: &TransitionWitnessV2) -> Hash32 {
    // Inbox outcomes remain in exact consumed order, including deterministic
    // rejections. Producer-controlled FIFO executions occur only after that
    // phase and are appended in their explicit vector order.
    let mut ids = witness
        .bond_inbox_outcomes
        .iter()
        .map(BondInboxProcessedOutcomeV2::outcome_hash)
        .collect::<Vec<_>>();
    ids.extend(
        witness
            .redemption_executions
            .iter()
            .map(RedemptionExecutionV2::action_id),
    );
    ordered_root("ECX/bond-actions-ordered-inbox/v2", &ids)
}

/// Verifies the complete additive V2 transition and emits only public values.
pub fn verify_transition_v2(
    witness: &TransitionWitnessV2,
) -> Result<TransitionJournalV2, ProtocolError> {
    verify_transition_v2_inner(witness)
}

// The implementation is split out to keep the public entry point stable for
// the zkVM guest while focused helpers below remain private.
fn verify_transition_v2_inner(
    witness: &TransitionWitnessV2,
) -> Result<TransitionJournalV2, ProtocolError> {
    let consumed_bond_inbox = validate_v2_linkage(witness)?;
    let (effects, base_journal) = verify_v2_actions_and_base(witness, &consumed_bond_inbox)?;
    let _ = effects;
    verify_v2_risk_and_funding(witness)?;
    verify_v2_deficit_and_mode(witness)?;
    build_journal(witness, &base_journal)
}

// Remaining verification helpers are implemented below.

fn forced_ioc_order_ids(witness: &TransitionWitnessV2) -> Result<BTreeSet<OrderId>, ProtocolError> {
    Ok(witness
        .base
        .forced_inbox
        .consumed()?
        .iter()
        .filter_map(|entry| match &entry.action {
            crate::forced::ForcedActionV1::ReduceOnlyIoc(order) => Some(order.order_id()),
            _ => None,
        })
        .collect())
}

fn verify_matcher_execution_linkage_v2(
    witness: &TransitionWitnessV2,
    forced_iocs: &BTreeSet<OrderId>,
) -> Result<(), ProtocolError> {
    let executions = witness
        .base
        .fills
        .iter()
        .filter(|pair| !forced_iocs.contains(&pair.taker_order.order_id()))
        .map(|pair| MatcherExecutionV2 {
            maker: &pair.maker_order,
            taker: &pair.taker_order,
            trade: &pair.trade,
        })
        .collect::<Vec<_>>();
    let (receipt_root, next_sequence) = verify_matcher_execution_batch_v2(
        &witness.configuration.base.matcher,
        witness.base.public.chain_id,
        witness.previous_state.matcher_execution_sequence,
        &executions,
        &witness.matcher_execution_receipts,
    )?;
    if witness.public.previous_matcher_execution_sequence
        != witness.previous_state.matcher_execution_sequence
        || witness.public.next_matcher_execution_sequence != next_sequence
        || witness.next_state.matcher_execution_sequence != next_sequence
        || witness.public.matcher_execution_receipt_batch_root != receipt_root
        || receipt_root
            != matcher_execution_receipt_batch_root_v2(&witness.matcher_execution_receipts)
    {
        return Err(ProtocolError::InvalidMatcherReceipt);
    }

    for receipt in &witness.matcher_execution_receipts {
        let body = &receipt.body;
        verify_execution_context_values_v2(
            witness.previous_state.last_transition_sidechain_height,
            witness.base.public.sidechain_height,
            witness.base.public.parent_height,
            witness.public.parent_mtp,
            body.observed_sidechain_height,
            body.execution_parent.height,
            body.execution_parent.median_time_past,
        )?;
    }
    Ok(())
}

fn verify_execution_context_values_v2(
    previous_sidechain_height: u64,
    current_sidechain_height: u64,
    current_parent_height: u64,
    current_parent_mtp: u64,
    observed_sidechain_height: u64,
    execution_parent_height: u64,
    execution_parent_mtp: u64,
) -> Result<(), ProtocolError> {
    // Equality with the previous singleton height is intentional: a matcher
    // may observe and sign after that transition within the same sidechain
    // block. A strictly older observation is replayable and rejected.
    // The parent locator, however, must be the exact authenticated transition
    // prior tip. A central matcher signature cannot authenticate that an older
    // ancestor was the live tip when the off-chain fill occurred, so accepting
    // a bounded ancestor would let it choose the funding hour.
    if observed_sidechain_height < previous_sidechain_height
        || observed_sidechain_height > current_sidechain_height
        || execution_parent_height != current_parent_height
        || execution_parent_mtp != current_parent_mtp
    {
        return Err(ProtocolError::InvalidMatcherReceipt);
    }
    Ok(())
}

fn validate_v2_linkage(
    witness: &TransitionWitnessV2,
) -> Result<Vec<BondInboxConsumedOutcomeV2>, ProtocolError> {
    let public = &witness.public;
    let previous = &witness.previous_state;
    let next = &witness.next_state;
    witness.configuration.validate()?;
    previous.validate()?;
    next.validate()?;
    let forced_iocs = forced_ioc_order_ids(witness)?;
    let expected_outcome_genesis = bond_inbox_outcome_genesis_root_v2(
        witness.configuration.bond_inbox_domain,
        witness.base.public.chain_id,
        public.configuration_hash,
    )?;
    if public.protocol_version != TransitionPublicInputsV2::VERSION
        || public.configuration_hash != witness.configuration.digest()
        || public.parent_mtp == 0
        || public.oracle_valid_through_mtp < public.parent_mtp
        || public.authenticated_min_price > witness.base.public.mark_price
        || witness.base.public.mark_price > public.authenticated_max_price
        || public.authenticated_price_range_commitment == [0; 32]
        || public.previous_state_root != previous.state_root()
        || public.next_state_root != next.state_root()
        || public.base_public_digest != witness.base.public.digest()
        || public.bond_action_root != bond_action_root_v2(witness)
        || public.order_risk_root != order_risk_root_v2(&witness.order_risk_commitments)
        || public.funding_state_root != next.funding.root()
        || previous.base != witness.base.previous_state
        || next.base != witness.base.next_state
        || witness.configuration.base.chain_id != witness.base.public.chain_id
        || witness.configuration.base.market != witness.base.public.market
        || witness.configuration.base.risk != witness.base.risk_params
        || previous.bond.bond_asset_id != witness.configuration.bond_asset_id
        || next.bond.bond_asset_id != witness.configuration.bond_asset_id
        || previous.bond.deployment_commitment != witness.configuration.bond_deployment_commitment
        || next.bond.deployment_commitment != witness.configuration.bond_deployment_commitment
        || previous.bond.inventory_covenant_hash
            != witness.configuration.bond_inventory_script_sha256
        || next.bond.inventory_covenant_hash != witness.configuration.bond_inventory_script_sha256
        || previous.active_order_risk_root
            != active_order_risk_root_v2(&witness.previous_active_order_risk_commitments)?
        || next.active_order_risk_root
            != active_order_risk_root_v2(&witness.next_active_order_risk_commitments)?
        || previous.position_risk_root != position_risk_root_v2(&witness.previous_position_risk)?
        || next.position_risk_root != position_risk_root_v2(&witness.next_position_risk)?
        || witness.base.public.sidechain_height <= previous.last_transition_sidechain_height
        || next.last_transition_sidechain_height != witness.base.public.sidechain_height
        || (previous.bond_inbox_outcome_count == 0
            && previous.bond_inbox_outcome_root != expected_outcome_genesis)
    {
        return Err(ProtocolError::InvalidBondState);
    }
    verify_matcher_execution_linkage_v2(witness, &forced_iocs)?;
    verify_persistent_risk_sets(witness)?;
    let bond_action_count = witness
        .bond_inbox
        .consumed_evidence
        .len()
        .checked_add(witness.redemption_executions.len())
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    let forced = witness.base.forced_inbox.consumed()?;
    // A consumed forced IOC that appears as an explicit taker fill is already
    // charged through the fill count. Count an unfilled forced IOC once, and
    // count forced cancellations/withdrawals once because they have no
    // duplicate entry in their corresponding explicit witness vectors.
    let forced_action_count = forced
        .iter()
        .filter(|entry| match &entry.action {
            crate::forced::ForcedActionV1::ReduceOnlyIoc(order) => !witness
                .base
                .fills
                .iter()
                .any(|pair| pair.taker_order.order_id() == order.order_id()),
            crate::forced::ForcedActionV1::Cancel(_)
            | crate::forced::ForcedActionV1::Withdraw(_) => true,
        })
        .count();
    let base_action_count = witness
        .base
        .deposits
        .len()
        .checked_add(witness.base.withdrawals.len())
        .and_then(|value| value.checked_add(witness.base.placements.len()))
        .and_then(|value| value.checked_add(witness.base.cancellations.len()))
        .and_then(|value| value.checked_add(witness.base.fills.len()))
        .and_then(|value| value.checked_add(witness.base.liquidations.len()))
        .and_then(|value| value.checked_add(forced_action_count))
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    let action_count = base_action_count
        .checked_add(bond_action_count)
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    if action_count > witness.configuration.base.maximum_transition_actions as usize {
        return Err(ProtocolError::InvalidBondState);
    }
    validate_queue(
        &witness.previous_redemption_queue,
        &witness.previous_state.bond,
    )?;
    validate_queue(&witness.next_redemption_queue, &witness.next_state.bond)?;
    if witness.previous_redemption_queue.len()
        > witness.configuration.bond_redemption_max_queue_entries as usize
        || witness.next_redemption_queue.len()
            > witness.configuration.bond_redemption_max_queue_entries as usize
    {
        return Err(ProtocolError::InvalidBondState);
    }
    let limits = BondInboxLimitsV2 {
        inbox_domain: witness.configuration.bond_inbox_domain,
        inclusion_blocks: witness.configuration.bond_inbox_inclusion_blocks,
        refund_minimum_parent_blocks: witness
            .configuration
            .bond_inbox_refund_minimum_parent_blocks,
        maximum_bundle_bytes: witness.configuration.bond_inbox_max_bundle_bytes,
        maximum_entries_per_sidechain_block: witness
            .configuration
            .bond_inbox_max_entries_per_sidechain_block,
        maximum_unique_source_witness_bytes_per_sidechain_block: witness
            .configuration
            .bond_inbox_max_unique_source_witness_bytes_per_sidechain_block,
        maximum_unique_source_transaction_bytes_per_sidechain_block: witness
            .configuration
            .bond_inbox_max_unique_source_transaction_bytes_per_sidechain_block,
        maximum_pending_entries_per_transition: witness
            .configuration
            .bond_inbox_max_pending_entries_per_transition,
        maximum_consumed_entries_per_transition: witness
            .configuration
            .bond_inbox_max_consumed_entries_per_transition,
    };
    witness.bond_inbox.verify(
        witness.base.public.chain_id,
        witness.public.configuration_hash,
        witness.previous_state.bond_inbox,
        witness.next_state.bond_inbox,
        witness.base.public.parent_height,
        witness.base.public.sidechain_height,
        witness.configuration.base.availability,
        limits,
    )
}

fn validate_queue(
    queue: &[RedemptionQueueEntryV2],
    state: &BondPublicStateV2,
) -> Result<(), ProtocolError> {
    let mut prior = None;
    let mut total = 0u64;
    for entry in queue {
        entry.validate()?;
        if entry.sequence < state.redemption_head
            || entry.sequence >= state.redemption_tail
            || prior.is_some_and(|sequence| entry.sequence <= sequence)
        {
            return Err(ProtocolError::InvalidBondState);
        }
        prior = Some(entry.sequence);
        total = total
            .checked_add(entry.remaining_share_atoms)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
    }
    let expected_head = queue
        .first()
        .map(|entry| entry.sequence)
        .unwrap_or(state.redemption_tail);
    if state.redemption_queue_root != redemption_queue_root_v2(queue)
        || state.redemption_head != expected_head
        || state.queued_redemption_share_atoms != total
    {
        return Err(ProtocolError::InvalidBondState);
    }
    Ok(())
}

fn refresh_bond_derived(state: &mut BondPublicStateV2) -> Result<(), ProtocolError> {
    state.target_reserve = target_reserve_125(state.full_bound_deficit)?;
    state.capital_mode = capital_mode_for(state.insurance_reserve, state.full_bound_deficit)?;
    Ok(())
}

fn verify_remainder_opening_commitment(
    remaining_share_atoms: u64,
    commitment: Hash32,
) -> Result<(), ProtocolError> {
    if (remaining_share_atoms == 0) != (commitment == [0; 32]) {
        Err(ProtocolError::InvalidBondState)
    } else {
        Ok(())
    }
}

fn advertised_bond_actions(
    witness: &TransitionWitnessV2,
) -> Result<BTreeMap<Hash32, BondInboxUserActionV2>, ProtocolError> {
    let mut advertised = BTreeMap::new();
    for action in witness
        .subscriptions
        .iter()
        .cloned()
        .map(BondInboxUserActionV2::Subscription)
        .chain(
            witness
                .recapitalization_contributions
                .iter()
                .cloned()
                .map(BondInboxUserActionV2::InsuranceRecapitalizationContribution),
        )
        .chain(
            witness
                .redemption_enqueues
                .iter()
                .cloned()
                .map(BondInboxUserActionV2::RedemptionEnqueue),
        )
        .chain(
            witness
                .redemption_cancellations
                .iter()
                .cloned()
                .map(BondInboxUserActionV2::RedemptionCancellation),
        )
    {
        if advertised.insert(action.action_id(), action).is_some() {
            return Err(ProtocolError::DuplicateRequest);
        }
    }
    Ok(advertised)
}

/// Reconstruct the account state immediately before ordered bond-inbox
/// processing. The base verifier applies accepted bond account actions last,
/// so reversing the producer's claimed accepted projection from the committed
/// final accounts yields the unique candidate starting state. Sequential
/// classification below then recomputes the accepted projection; any attempt
/// to omit a valid request or include an invalid one disagrees exactly.
fn rejection_for_invalid_subscription_quote(error: ProtocolError) -> BondInboxRejectionV2 {
    match error {
        ProtocolError::InsufficientCollateral => BondInboxRejectionV2::InsufficientCollateral,
        _ => BondInboxRejectionV2::InvalidSubscriptionQuote,
    }
}

fn validate_bond_account_debit_v2(
    account: Option<&AccountLeaf>,
    account_nonce: u64,
    amount: u64,
) -> Result<(), BondInboxRejectionV2> {
    let account = account.ok_or(BondInboxRejectionV2::InvalidNonce)?;
    if account.account_nonce != account_nonce || account.account_nonce == u64::MAX {
        return Err(BondInboxRejectionV2::InvalidNonce);
    }
    if account.collateral.0 < i128::from(amount) {
        return Err(BondInboxRejectionV2::InsufficientCollateral);
    }
    Ok(())
}

fn consume_bond_account_nonce_v2(
    accounts: &mut BTreeMap<[u8; 32], AccountLeaf>,
    effects: &mut V2ExternalEffects,
    signer: XOnlyKey,
    account_nonce: u64,
    amount: u64,
) -> Result<(), ProtocolError> {
    let account = accounts
        .get_mut(&signer.0)
        .ok_or(ProtocolError::InvalidBondState)?;
    if account.account_nonce != account_nonce || account.account_nonce == u64::MAX {
        return Err(ProtocolError::InvalidNonce);
    }
    account.account_nonce += 1;
    if amount != 0 {
        account.collateral = account.collateral.checked_sub(Amount(i128::from(amount)))?;
    }
    effects
        .account_debits
        .push((signer, account_nonce, Amount(i128::from(amount))));
    Ok(())
}

/// Authenticated user requests consume a live account nonce even when their
/// current economic evaluation rejects. This turns that signed intent into a
/// one-shot nullifier and prevents a copied wrong-quote/mode/queue-full action
/// from becoming valid after state changes. Every such rejection emits an
/// explicit zero-amount debit: only an accepted action can move collateral.
fn rejection_nonce_debit_amount_v2(rejection: BondInboxRejectionV2) -> Option<u64> {
    match rejection {
        BondInboxRejectionV2::MalformedOrInvalidAction
        | BondInboxRejectionV2::InvalidContext
        | BondInboxRejectionV2::InvalidNonce
        | BondInboxRejectionV2::DuplicateOrReplayedAction => None,
        BondInboxRejectionV2::InsufficientCollateral
        | BondInboxRejectionV2::InvalidSubscriptionQuote
        | BondInboxRejectionV2::CapitalModeRestriction
        | BondInboxRejectionV2::InvalidQueueRequest
        | BondInboxRejectionV2::InvalidRecapitalizationContribution => Some(0),
    }
}

fn validated_subscription_quote_v2(
    state: BondPublicStateV2,
    action: &BondSubscriptionV2,
) -> Result<SubscriptionOutcomeV2, BondInboxRejectionV2> {
    match apply_subscription(state, u128::from(action.contribution_usdd_atoms)) {
        Ok(outcome) if outcome.issued_share_atoms == action.issued_share_atoms => Ok(outcome),
        Ok(_) => Err(BondInboxRejectionV2::InvalidSubscriptionQuote),
        Err(error) => Err(rejection_for_invalid_subscription_quote(error)),
    }
}

fn validate_enqueue_admission_v2(
    state: BondPublicStateV2,
    queue_len: usize,
    maximum_queue_entries: u32,
    source_parent_height: u64,
    refund_minimum_parent_blocks: u32,
    action: &RedemptionEnqueueV2,
) -> Result<(), BondInboxRejectionV2> {
    if state.capital_mode != CapitalModeV2::Normal {
        return Err(BondInboxRejectionV2::CapitalModeRestriction);
    }
    if source_parent_height
        .checked_add(u64::from(refund_minimum_parent_blocks))
        .map_or(true, |minimum_refund_height| {
            action.refund_not_before_parent_height < minimum_refund_height
        })
        || !redemption_queue_has_capacity_v2(queue_len, maximum_queue_entries)
        || state.redemption_tail == u64::MAX
    {
        return Err(BondInboxRejectionV2::InvalidQueueRequest);
    }
    Ok(())
}

fn validated_redemption_cancellation_v2(
    state: BondPublicStateV2,
    queue: &[RedemptionQueueEntryV2],
    action: &RedemptionCancellationV2Action,
) -> Result<(usize, RedemptionCancellationV2), BondInboxRejectionV2> {
    if state.capital_mode == CapitalModeV2::RecapitalizationOnly {
        return Err(BondInboxRejectionV2::CapitalModeRestriction);
    }
    let index = queue
        .iter()
        .position(|entry| {
            entry.sequence == action.sequence && entry.request_id == action.request_id
        })
        .ok_or(BondInboxRejectionV2::InvalidQueueRequest)?;
    let entry = queue[index];
    if entry.claimant_commitment != tagged_hash("ECX/bond-claimant/v2", &action.claimant.0) {
        return Err(BondInboxRejectionV2::InvalidQueueRequest);
    }
    plan_redemption_cancellation(state, entry)
        .map(|outcome| (index, outcome))
        .map_err(|_| BondInboxRejectionV2::InvalidQueueRequest)
}

fn verify_v2_actions_and_base(
    witness: &TransitionWitnessV2,
    consumed: &[BondInboxConsumedOutcomeV2],
) -> Result<(V2ExternalEffects, TransitionJournal), ProtocolError> {
    let mut state = witness.previous_state.bond;
    state.insurance_reserve = witness.public.insurance_reserve_before_bond_actions;
    // Bond actions execute against the deficit of the complete proposed
    // portfolio, not the prior transition's target. This makes a partial FIFO
    // redemption preserve the actual post-trade 125% target instead of either
    // over-redeeming or rejecting a smaller safe partial amount.
    state.full_bound_deficit = calculate_next_full_bound_deficit(witness)?;
    refresh_bond_derived(&mut state)?;
    state.validate()?;
    let mut queue = witness.previous_redemption_queue.clone();
    let mut effects = V2ExternalEffects::default();
    let mut seen_actions = BTreeSet::new();
    let mut subscription_ids = BTreeSet::new();
    let mut recapitalization_contribution_ids = BTreeSet::new();
    let mut enqueued_requests = BTreeSet::new();
    let mut executed_requests = BTreeSet::new();
    let advertised = advertised_bond_actions(witness)?;
    let selections = verify_order_risk_commitments(witness)?;
    let starting_position_margin_bps = witness
        .previous_position_risk
        .iter()
        .map(|leaf| (leaf.trader.0, leaf.selected_initial_margin_bps))
        .collect::<BTreeMap<_, _>>();
    let mut accounts = v2_accounts_before_external(
        &witness.base,
        selections.clone(),
        starting_position_margin_bps.clone(),
    )?;
    let mut accepted_subscriptions = Vec::new();
    let mut accepted_recapitalization_contributions = Vec::new();
    let mut accepted_enqueues = Vec::new();
    let mut accepted_cancellations = Vec::new();
    let mut processed_outcomes = Vec::with_capacity(consumed.len());

    for consumed_outcome in consumed {
        let mut rejection = None;
        let mut rejection_nonce = None;
        if consumed_outcome.disposition == BondInboxConsumedDispositionV2::ExpiredUnavailable {
            processed_outcomes.push(BondInboxProcessedOutcomeV2::expired_unavailable(
                consumed_outcome,
            ));
            continue;
        }
        let BondInboxConsumedDispositionV2::Action(action) = &consumed_outcome.disposition else {
            return Err(ProtocolError::InvalidBondInbox);
        };
        match action {
            Err(reason) => rejection = Some(*reason),
            Ok(BondInboxUserActionV2::Subscription(signed)) => {
                let action = &signed.action;
                if action.chain_id != witness.base.public.chain_id
                    || action.configuration_hash != witness.public.configuration_hash
                {
                    rejection = Some(BondInboxRejectionV2::InvalidContext);
                } else if seen_actions.contains(&action.action_id())
                    || subscription_ids.contains(&action.subscription_id())
                {
                    rejection = Some(BondInboxRejectionV2::DuplicateOrReplayedAction);
                } else if let Err(reason) = validate_bond_account_debit_v2(
                    accounts.get(&action.trader.0),
                    action.account_nonce,
                    0,
                ) {
                    rejection = Some(reason);
                } else if accounts.get(&action.trader.0).is_some_and(|account| {
                    account.collateral.0 < i128::from(action.contribution_usdd_atoms)
                }) {
                    rejection = Some(BondInboxRejectionV2::InsufficientCollateral);
                    rejection_nonce = Some((action.trader, action.account_nonce, 0));
                } else {
                    match validated_subscription_quote_v2(state, action) {
                        Ok(outcome) => {
                            consume_bond_account_nonce_v2(
                                &mut accounts,
                                &mut effects,
                                action.trader,
                                action.account_nonce,
                                action.contribution_usdd_atoms,
                            )?;
                            state.insurance_reserve = outcome.insurance_reserve_after;
                            state.outstanding_share_atoms = outcome.outstanding_share_atoms_after;
                            state.inventory_share_atoms = outcome.inventory_share_atoms_after;
                            refresh_bond_derived(&mut state)?;
                            effects.insurance_delta = effects
                                .insurance_delta
                                .checked_add(Amount(i128::from(action.contribution_usdd_atoms)))?;
                            seen_actions.insert(action.action_id());
                            subscription_ids.insert(action.subscription_id());
                            accepted_subscriptions.push(signed.clone());
                        }
                        Err(reason) => {
                            rejection_nonce = rejection_nonce_debit_amount_v2(reason)
                                .map(|amount| (action.trader, action.account_nonce, amount));
                            rejection = Some(reason);
                        }
                    }
                }
            }
            Ok(BondInboxUserActionV2::InsuranceRecapitalizationContribution(signed)) => {
                let action = &signed.action;
                if action.chain_id != witness.base.public.chain_id
                    || action.configuration_hash != witness.public.configuration_hash
                {
                    rejection = Some(BondInboxRejectionV2::InvalidContext);
                } else if seen_actions.contains(&action.action_id())
                    || recapitalization_contribution_ids.contains(&action.contribution_id())
                {
                    rejection = Some(BondInboxRejectionV2::DuplicateOrReplayedAction);
                } else if let Err(reason) = validate_bond_account_debit_v2(
                    accounts.get(&action.contributor.0),
                    action.account_nonce,
                    0,
                ) {
                    rejection = Some(reason);
                } else if accounts.get(&action.contributor.0).is_some_and(|account| {
                    account.collateral.0 < i128::from(action.contribution_usdd_atoms)
                }) {
                    rejection = Some(BondInboxRejectionV2::InsufficientCollateral);
                    rejection_nonce = Some((action.contributor, action.account_nonce, 0));
                } else if let Some(reserve_after) = state
                    .insurance_reserve
                    .checked_add(u128::from(action.contribution_usdd_atoms))
                {
                    consume_bond_account_nonce_v2(
                        &mut accounts,
                        &mut effects,
                        action.contributor,
                        action.account_nonce,
                        action.contribution_usdd_atoms,
                    )?;
                    state.insurance_reserve = reserve_after;
                    refresh_bond_derived(&mut state)?;
                    effects.insurance_delta = effects
                        .insurance_delta
                        .checked_add(Amount(i128::from(action.contribution_usdd_atoms)))?;
                    seen_actions.insert(action.action_id());
                    recapitalization_contribution_ids.insert(action.contribution_id());
                    accepted_recapitalization_contributions.push(signed.clone());
                } else {
                    let reason = BondInboxRejectionV2::InvalidRecapitalizationContribution;
                    rejection_nonce = Some((action.contributor, action.account_nonce, 0));
                    rejection = Some(reason);
                }
            }
            Ok(BondInboxUserActionV2::RedemptionEnqueue(signed)) => {
                let action = &signed.action;
                if action.chain_id != witness.base.public.chain_id
                    || action.configuration_hash != witness.public.configuration_hash
                {
                    rejection = Some(BondInboxRejectionV2::InvalidContext);
                } else if seen_actions.contains(&action.action_id()) {
                    rejection = Some(BondInboxRejectionV2::DuplicateOrReplayedAction);
                } else if let Err(reason) = validate_bond_account_debit_v2(
                    accounts.get(&action.claimant.0),
                    action.account_nonce,
                    0,
                ) {
                    rejection = Some(reason);
                } else if let Err(reason) = validate_enqueue_admission_v2(
                    state,
                    queue.len(),
                    witness.configuration.bond_redemption_max_queue_entries,
                    consumed_outcome.source_parent_height,
                    witness
                        .configuration
                        .bond_inbox_refund_minimum_parent_blocks,
                    action,
                ) {
                    rejection_nonce = Some((action.claimant, action.account_nonce, 0));
                    rejection = Some(reason);
                } else {
                    match action.queue_entry(
                        state.redemption_tail,
                        consumed_outcome.entry_hash,
                        consumed_outcome.source_parent_height,
                    ) {
                        Ok(entry) => {
                            let queued_after = state
                                .queued_redemption_share_atoms
                                .checked_add(entry.remaining_share_atoms);
                            if let Some(queued_after) = queued_after
                                .filter(|value| *value <= state.outstanding_share_atoms)
                                .filter(|_| enqueued_requests.insert(entry.request_id))
                            {
                                state.redemption_tail += 1;
                                state.queued_redemption_share_atoms = queued_after;
                                consume_bond_account_nonce_v2(
                                    &mut accounts,
                                    &mut effects,
                                    action.claimant,
                                    action.account_nonce,
                                    0,
                                )?;
                                queue.push(entry);
                                seen_actions.insert(action.action_id());
                                accepted_enqueues.push(signed.clone());
                            } else {
                                rejection_nonce = Some((action.claimant, action.account_nonce, 0));
                                rejection = Some(BondInboxRejectionV2::InvalidQueueRequest);
                            }
                        }
                        Err(_) => {
                            rejection_nonce = Some((action.claimant, action.account_nonce, 0));
                            rejection = Some(BondInboxRejectionV2::InvalidQueueRequest);
                        }
                    }
                }
            }
            Ok(BondInboxUserActionV2::RedemptionCancellation(signed)) => {
                let action = &signed.action;
                if action.chain_id != witness.base.public.chain_id
                    || action.configuration_hash != witness.public.configuration_hash
                {
                    rejection = Some(BondInboxRejectionV2::InvalidContext);
                } else if seen_actions.contains(&action.action_id()) {
                    rejection = Some(BondInboxRejectionV2::DuplicateOrReplayedAction);
                } else {
                    match validated_redemption_cancellation_v2(state, &queue, action) {
                        Ok((index, cancellation)) => {
                            state.queued_redemption_share_atoms =
                                cancellation.queued_redemption_share_atoms_after;
                            queue.remove(index);
                            state.redemption_head = queue
                                .first()
                                .map(|entry| entry.sequence)
                                .unwrap_or(state.redemption_tail);
                            seen_actions.insert(action.action_id());
                            accepted_cancellations.push(signed.clone());
                        }
                        Err(reason) => rejection = Some(reason),
                    }
                }
            }
        }
        if let Some((signer, nonce, amount)) = rejection_nonce {
            consume_bond_account_nonce_v2(&mut accounts, &mut effects, signer, nonce, amount)?;
        }
        processed_outcomes.push(match rejection {
            None => BondInboxProcessedOutcomeV2::accepted(consumed_outcome),
            Some(reason) => BondInboxProcessedOutcomeV2::rejected(consumed_outcome, reason),
        });
    }

    if accepted_subscriptions != witness.subscriptions
        || accepted_recapitalization_contributions != witness.recapitalization_contributions
        || accepted_enqueues != witness.redemption_enqueues
        || accepted_cancellations != witness.redemption_cancellations
        || processed_outcomes != witness.bond_inbox_outcomes
        || advertised.len()
            != accepted_subscriptions.len()
                + accepted_recapitalization_contributions.len()
                + accepted_enqueues.len()
                + accepted_cancellations.len()
    {
        return Err(ProtocolError::InvalidBondInbox);
    }

    let mut outcome_root = witness.previous_state.bond_inbox_outcome_root;
    for outcome in &processed_outcomes {
        outcome_root = bond_inbox_outcome_next_root_v2(outcome_root, outcome)?;
    }
    let outcome_count = witness
        .previous_state
        .bond_inbox_outcome_count
        .checked_add(
            u64::try_from(processed_outcomes.len())
                .map_err(|_| ProtocolError::ArithmeticOverflow)?,
        )
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    if outcome_root != witness.next_state.bond_inbox_outcome_root
        || outcome_count != witness.next_state.bond_inbox_outcome_count
    {
        return Err(ProtocolError::InvalidBondInbox);
    }

    for execution in &witness.redemption_executions {
        execution.validate()?;
        if state.capital_mode != CapitalModeV2::Normal
            || !executed_requests.insert(execution.request_id)
            || !seen_actions.insert(execution.action_id())
        {
            return Err(ProtocolError::InvalidBondState);
        }
        let entry = *queue.first().ok_or(ProtocolError::InvalidBondState)?;
        if execution.sequence != entry.sequence || execution.request_id != entry.request_id {
            return Err(ProtocolError::InvalidBondState);
        }
        let outcome = plan_fifo_redemption(state, entry, witness.base.public.parent_height)?
            .ok_or(ProtocolError::InsufficientCollateral)?;
        if execution.redeemed_share_atoms != outcome.redeemed_share_atoms
            || execution.paid_usdd_atoms != outcome.paid_usdd_atoms
        {
            return Err(ProtocolError::InvalidBondState);
        }
        verify_remainder_opening_commitment(
            outcome.remaining_entry_share_atoms,
            execution.queue_remainder_output_opening_commitment,
        )?;
        state.insurance_reserve = outcome.insurance_reserve_after;
        state.outstanding_share_atoms = outcome.outstanding_share_atoms_after;
        state.inventory_share_atoms = outcome.inventory_share_atoms_after;
        state.queued_redemption_share_atoms = outcome.queued_redemption_share_atoms_after;
        if outcome.remaining_entry_share_atoms == 0 {
            queue.remove(0);
        } else {
            queue[0].remaining_share_atoms = outcome.remaining_entry_share_atoms;
        }
        state.redemption_head = queue
            .first()
            .map(|entry| entry.sequence)
            .unwrap_or(state.redemption_tail);
        refresh_bond_derived(&mut state)?;
        let payment = i128::try_from(outcome.paid_usdd_atoms)
            .map_err(|_| ProtocolError::ArithmeticOverflow)?;
        effects.insurance_delta = effects.insurance_delta.checked_sub(Amount(payment))?;
        effects.withdrawal_delta = effects.withdrawal_delta.checked_add(Amount(payment))?;
    }

    state.redemption_head = queue
        .first()
        .map(|entry| entry.sequence)
        .unwrap_or(state.redemption_tail);
    state.redemption_queue_root = redemption_queue_root_v2(&queue);
    if queue != witness.next_redemption_queue {
        return Err(ProtocolError::InvalidBondState);
    }
    let next = witness.next_state.bond;
    if state.insurance_reserve != next.insurance_reserve
        || state.issued_share_atoms != next.issued_share_atoms
        || state.outstanding_share_atoms != next.outstanding_share_atoms
        || state.inventory_share_atoms != next.inventory_share_atoms
        || state.redemption_queue_root != next.redemption_queue_root
        || state.redemption_head != next.redemption_head
        || state.redemption_tail != next.redemption_tail
        || state.queued_redemption_share_atoms != next.queued_redemption_share_atoms
    {
        return Err(ProtocolError::InvalidBondState);
    }

    effects.selected_margin_bps = Some(selections);
    effects.starting_position_margin_bps = Some(starting_position_margin_bps);
    let net = effects.insurance_delta.0;
    let expected_pre = i128::try_from(next.insurance_reserve)
        .map_err(|_| ProtocolError::ArithmeticOverflow)?
        .checked_sub(net)
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    if expected_pre < 0
        || u128::try_from(expected_pre).map_err(|_| ProtocolError::ArithmeticOverflow)?
            != witness.public.insurance_reserve_before_bond_actions
    {
        return Err(ProtocolError::ConservationViolation);
    }
    let journal = verify_transition_v2_base(&witness.base, &effects)?;
    Ok((effects, journal))
}

fn verify_order_risk_commitments(
    witness: &TransitionWitnessV2,
) -> Result<BTreeMap<OrderId, u32>, ProtocolError> {
    let mut map = BTreeMap::new();
    for commitment in &witness.order_risk_commitments {
        commitment.verify(witness.base.risk_params)?;
        if commitment.configuration_hash != witness.public.configuration_hash
            || map
                .insert(commitment.order_id, commitment.selected_initial_margin_bps)
                .is_some()
        {
            return Err(ProtocolError::DuplicateRequest);
        }
    }
    let mut required = BTreeMap::new();
    for placement in &witness.base.placements {
        required.insert(placement.order.order_id(), placement.order.order.trader);
    }
    for pair in &witness.base.fills {
        required.insert(pair.maker_order.order_id(), pair.maker_order.order.trader);
        required.insert(pair.taker_order.order_id(), pair.taker_order.order.trader);
    }
    for liquidation in &witness.base.liquidations {
        required.insert(
            liquidation.maker_order.order_id(),
            liquidation.maker_order.order.trader,
        );
    }
    for (order_id, trader) in required {
        let commitment = witness
            .order_risk_commitments
            .iter()
            .find(|commitment| commitment.order_id == order_id)
            .ok_or(ProtocolError::TransitionMismatch(
                "missing signed order margin",
            ))?;
        if commitment.trader != trader {
            return Err(ProtocolError::InvalidSignature);
        }
        if witness
            .previous_active_order_risk_commitments
            .iter()
            .find(|previous| previous.order_id == order_id)
            .is_some_and(|previous| previous != commitment)
        {
            return Err(ProtocolError::InvalidBondState);
        }
    }
    let required_count = witness
        .base
        .placements
        .iter()
        .map(|placement| placement.order.order_id())
        .chain(
            witness
                .base
                .fills
                .iter()
                .flat_map(|pair| [pair.maker_order.order_id(), pair.taker_order.order_id()]),
        )
        .chain(
            witness
                .base
                .liquidations
                .iter()
                .map(|liquidation| liquidation.maker_order.order_id()),
        )
        .collect::<BTreeSet<_>>()
        .len();
    if map.len() != required_count {
        return Err(ProtocolError::InvalidBondState);
    }
    derive_effective_position_risk(witness, &map)
}

struct PositionRiskReplay<'a> {
    proof_floor: u32,
    signed: &'a BTreeMap<OrderId, u32>,
    positions: BTreeMap<[u8; 32], Position>,
    margins: BTreeMap<[u8; 32], u32>,
    effective: BTreeMap<OrderId, u32>,
}

impl PositionRiskReplay<'_> {
    fn apply_order(
        &mut self,
        trader: XOnlyKey,
        order_id: OrderId,
        side: crate::order::Side,
        quantity: crate::types::Quantity,
        price: Price,
    ) -> Result<(), ProtocolError> {
        let old = *self
            .positions
            .get(&trader.0)
            .ok_or(ProtocolError::InvalidBondState)?;
        let selected = *self
            .signed
            .get(&order_id)
            .ok_or(ProtocolError::InvalidBondState)?;
        let current = *self
            .margins
            .get(&trader.0)
            .ok_or(ProtocolError::InvalidBondState)?;
        let next = crate::risk::apply_fill(old, side, quantity, price)?.position;
        let increases_risk = creates_directional_risk(old, next);
        let next_margin = if next.size == 0 {
            self.proof_floor
        } else if increases_risk {
            current.max(selected)
        } else {
            current
        };
        if increases_risk {
            self.effective.insert(order_id, current.max(selected));
        }
        self.positions.insert(trader.0, next);
        self.margins.insert(trader.0, next_margin);
        Ok(())
    }
}

fn derive_effective_position_risk(
    witness: &TransitionWitnessV2,
    signed: &BTreeMap<OrderId, u32>,
) -> Result<BTreeMap<OrderId, u32>, ProtocolError> {
    let mut replay = PositionRiskReplay {
        proof_floor: witness.base.risk_params.initial_margin_bps,
        signed,
        positions: witness
            .base
            .previous_positions
            .iter()
            .map(|leaf| (leaf.trader.0, leaf.position))
            .collect(),
        margins: witness
            .previous_position_risk
            .iter()
            .map(|leaf| (leaf.trader.0, leaf.selected_initial_margin_bps))
            .collect(),
        effective: signed.clone(),
    };

    for pair in &witness.base.fills {
        replay.apply_order(
            pair.maker_order.order.trader,
            pair.maker_order.order_id(),
            pair.trade.maker_side,
            pair.trade.quantity,
            pair.trade.price,
        )?;
        replay.apply_order(
            pair.taker_order.order.trader,
            pair.taker_order.order_id(),
            pair.trade.maker_side.opposite(),
            pair.trade.quantity,
            pair.trade.price,
        )?;
    }
    for liquidation in &witness.base.liquidations {
        let maker = &liquidation.maker_order;
        replay.apply_order(
            maker.order.trader,
            maker.order_id(),
            maker.order.side,
            liquidation.quantity,
            maker.order.limit_price,
        )?;
        let old = *replay
            .positions
            .get(&liquidation.target.0)
            .ok_or(ProtocolError::InvalidBondState)?;
        let side = if old.size > 0 {
            crate::order::Side::Sell
        } else {
            crate::order::Side::Buy
        };
        let next =
            crate::risk::apply_fill(old, side, liquidation.quantity, maker.order.limit_price)?
                .position;
        replay.positions.insert(liquidation.target.0, next);
        if next.size == 0 {
            replay.margins.insert(
                liquidation.target.0,
                witness.base.risk_params.initial_margin_bps,
            );
        }
    }
    let committed = witness
        .next_position_risk
        .iter()
        .map(|leaf| (leaf.trader.0, leaf.selected_initial_margin_bps))
        .collect::<BTreeMap<_, _>>();
    if replay.margins != committed {
        return Err(ProtocolError::InvalidBondState);
    }
    Ok(replay.effective)
}

fn open_interest_notional_before_fills_v2(
    witness: &TransitionWitnessV2,
) -> Result<u128, ProtocolError> {
    // Funding is applied to the entire previous position inventory before any
    // fill in this transition. On an epoch roll, the funding relation rejects
    // every old-epoch execution receipt, so all current fills belong to the
    // new active epoch and cannot change its epoch-start open interest.
    open_interest_notional_at_mark(
        &witness.base.previous_positions,
        witness.previous_state.funding.last_oracle_mark,
    )
}

fn open_interest_notional_at_mark(
    positions: &[PositionLeaf],
    boundary_mark: Price,
) -> Result<u128, ProtocolError> {
    positions
        .iter()
        .filter(|position| position.position.size > 0)
        .try_fold(0u128, |total, position| {
            let value = notional(boundary_mark, position.position.size.unsigned_abs())?;
            total
                .checked_add(
                    u128::try_from(value.0).map_err(|_| ProtocolError::ArithmeticOverflow)?,
                )
                .ok_or(ProtocolError::ArithmeticOverflow)
        })
}

fn verified_funding_observations(
    witness: &TransitionWitnessV2,
) -> Result<Vec<TimestampedFundingObservationV2>, ProtocolError> {
    let mut observations =
        Vec::with_capacity(witness.base.fills.len() + witness.base.liquidations.len());
    for pair in &witness.base.fills {
        // A fill is economically final only in this authenticated transition.
        // The central matcher proves exact price/quantity/order relation, but
        // never chooses the funding timestamp. Forced and ordinary fills use
        // the same proof-bound prior-parent MTP.
        observations.push(TimestampedFundingObservationV2::new(
            pair.trade.price,
            pair.trade.quantity,
            witness.public.parent_mtp,
        )?);
    }
    // Liquidation executions are proof-verified, matcher-independent trades.
    // Their deterministic timestamp is the authenticated transition parent MTP.
    for liquidation in &witness.base.liquidations {
        observations.push(liquidation_funding_observation_v2(
            liquidation,
            witness.public.parent_mtp,
        )?);
    }
    Ok(observations)
}

fn liquidation_funding_observation_v2(
    liquidation: &crate::transition::LiquidationMatchV1,
    parent_mtp: u64,
) -> Result<TimestampedFundingObservationV2, ProtocolError> {
    TimestampedFundingObservationV2::new(
        liquidation.maker_order.order.limit_price,
        liquidation.quantity,
        parent_mtp,
    )
}

fn verify_v2_risk_and_funding(witness: &TransitionWitnessV2) -> Result<(), ProtocolError> {
    let observations = verified_funding_observations(witness)?;
    let (expected, settled_rate) = advance_funding_timestamped_v2(
        &witness.previous_state.funding,
        witness.public.parent_mtp,
        witness.base.public.mark_price,
        // Funding manipulation is bounded by the current authenticated
        // hybrid-oracle safety band. The much wider frozen scalar endpoints
        // are reserved for portfolio-deficit coverage and would not be an
        // adequate clamp for an eight-hour trade VWAP.
        witness.base.public.liquidation_low,
        witness.base.public.liquidation_high,
        witness.public.oracle_valid_through_mtp,
        &observations,
        open_interest_notional_before_fills_v2(witness)?,
    )?;
    if expected != witness.next_state.funding
        || witness.base.public.funding_rate_ppm != settled_rate
        || witness.next_state.base.funding_index
            != witness
                .previous_state
                .base
                .funding_index
                .checked_add(i128::from(settled_rate))
                .ok_or(ProtocolError::ArithmeticOverflow)?
    {
        return Err(ProtocolError::InvalidFundingState);
    }
    Ok(())
}

fn account_map(
    accounts: &[AccountLeaf],
) -> Result<BTreeMap<[u8; 32], &AccountLeaf>, ProtocolError> {
    let mut map = BTreeMap::new();
    for account in accounts {
        if map.insert(account.trader.0, account).is_some() {
            return Err(ProtocolError::DuplicateMerkleKey);
        }
    }
    Ok(map)
}

fn endpoint_equities(
    accounts: &BTreeMap<[u8; 32], &AccountLeaf>,
    positions: &[PositionLeaf],
    endpoint: Price,
    params: RiskParams,
) -> Result<Vec<i128>, ProtocolError> {
    positions
        .iter()
        .map(|position| {
            let account = accounts
                .get(&position.trader.0)
                .ok_or(ProtocolError::TransitionMismatch("deficit account"))?;
            let before_funding = equity(account.collateral, &position.position, endpoint)?.0;
            let quote =
                u128::try_from(notional(endpoint, position.position.size.unsigned_abs())?.0)
                    .map_err(|_| ProtocolError::ArithmeticOverflow)?;
            let numerator = quote
                .checked_mul(u128::from(params.max_abs_funding_rate_ppm))
                .ok_or(ProtocolError::ArithmeticOverflow)?;
            let worst_funding = numerator
                .checked_add(999_999)
                .ok_or(ProtocolError::ArithmeticOverflow)?
                / 1_000_000;
            before_funding
                .checked_sub(
                    i128::try_from(worst_funding).map_err(|_| ProtocolError::ArithmeticOverflow)?,
                )
                .ok_or(ProtocolError::ArithmeticOverflow)
        })
        .collect()
}

fn calculate_full_bound_deficit(
    accounts: &[AccountLeaf],
    positions: &[PositionLeaf],
    minimum: Price,
    maximum: Price,
    params: RiskParams,
) -> Result<u128, ProtocolError> {
    let accounts = account_map(accounts)?;
    let low = endpoint_equities(&accounts, positions, minimum, params)?;
    let high = endpoint_equities(&accounts, positions, maximum, params)?;
    full_range_deficit(&low, &high)
}

fn calculate_next_full_bound_deficit(witness: &TransitionWitnessV2) -> Result<u128, ProtocolError> {
    calculate_full_bound_deficit(
        &witness.base.next_accounts,
        &witness.base.next_positions,
        witness.public.authenticated_min_price,
        witness.public.authenticated_max_price,
        witness.base.risk_params,
    )
}

fn calculate_previous_full_bound_deficit_at_current_range(
    witness: &TransitionWitnessV2,
) -> Result<u128, ProtocolError> {
    calculate_full_bound_deficit(
        &witness.base.previous_accounts,
        &witness.base.previous_positions,
        witness.public.authenticated_min_price,
        witness.public.authenticated_max_price,
        witness.base.risk_params,
    )
}

fn verify_operational_position_safety(
    accounts: &BTreeMap<[u8; 32], &AccountLeaf>,
    positions: &[PositionLeaf],
    liquidation_low: Price,
    liquidation_high: Price,
    params: RiskParams,
    allow_unsafe_recap: bool,
) -> Result<(), ProtocolError> {
    if allow_unsafe_recap {
        return Ok(());
    }
    for position in positions {
        if position.position.size == 0 {
            continue;
        }
        let adverse = if position.position.size > 0 {
            liquidation_low
        } else {
            liquidation_high
        };
        let account = accounts
            .get(&position.trader.0)
            .ok_or(ProtocolError::TransitionMismatch("adverse margin account"))?;
        let maintenance =
            required_margin(&position.position, adverse, MarginKind::Maintenance, params)?;
        if equity(account.collateral, &position.position, adverse)?.0 < maintenance.0 {
            return Err(ProtocolError::InsufficientCollateral);
        }
    }
    Ok(())
}

fn verify_capital_action_permissions(
    next_mode: CapitalModeV2,
    capital_only_transition: bool,
    has_withdrawal: bool,
    has_redemption_enqueue: bool,
    has_redemption_execution: bool,
    has_non_reduce_order: bool,
) -> Result<(), ProtocolError> {
    if (has_withdrawal
        || has_redemption_enqueue
        || has_redemption_execution
        || has_non_reduce_order)
        && next_mode != CapitalModeV2::Normal
    {
        return Err(ProtocolError::InsufficientCollateral);
    }
    if next_mode == CapitalModeV2::RecapitalizationOnly && !capital_only_transition {
        return Err(ProtocolError::InvalidBondState);
    }
    Ok(())
}

/// A predecessor that is non-normal under the *current authenticated range*
/// cannot bootstrap permission for new exposure from the economic effects of
/// that same exposure. Recomputing here is essential: the predecessor's
/// stored mode may have been derived under an older, narrower oracle range.
/// The sole protocol-authorized bridge back to normal trading is an accepted
/// inbox capital contribution (subscription or non-dilutive recapitalization)
/// committed in the same transition; final state must still reach 125%.
fn verify_atomic_recapitalization_source(
    predecessor_mode_at_current_range: CapitalModeV2,
    has_capital_contribution: bool,
    has_non_reduce_order: bool,
) -> Result<(), ProtocolError> {
    if predecessor_mode_at_current_range != CapitalModeV2::Normal
        && has_non_reduce_order
        && !has_capital_contribution
    {
        return Err(ProtocolError::InsufficientCollateral);
    }
    Ok(())
}

/// A portfolio that is below 100% coverage may not use trading, liquidation,
/// queue, collateral, or forced actions as an implicit recapitalization path.
/// It must first advance through a capital-only transition, unless an accepted
/// capital contribution in this same transition restores the final state to
/// Normal. That atomic recovery/new-risk exception remains subject to 125%.
fn verify_recovery_predecessor_permissions(
    predecessor_mode_at_current_range: CapitalModeV2,
    has_capital_contribution: bool,
    next_mode: CapitalModeV2,
    has_other_discretionary_action: bool,
) -> Result<(), ProtocolError> {
    if predecessor_mode_at_current_range == CapitalModeV2::RecapitalizationOnly
        && has_other_discretionary_action
        && (!has_capital_contribution || next_mode != CapitalModeV2::Normal)
    {
        return Err(ProtocolError::InsufficientCollateral);
    }
    Ok(())
}

fn capital_shortfall_v2(reserve: u128, deficit: u128) -> Result<u128, ProtocolError> {
    let target = target_reserve_125(deficit)?;
    Ok(target - reserve.min(target))
}

/// Capital-only recovery must make genuine progress under the same current
/// authenticated range. The successor deficit includes the contributor's
/// account debit, so moving collateral into insurance cannot masquerade as a
/// recap if portfolio deficit rises by as much or more.
fn verify_capital_only_recovery_progress(
    predecessor_reserve: u128,
    predecessor_deficit_at_current_range: u128,
    successor_reserve: u128,
    successor_deficit: u128,
    has_capital_contribution: bool,
    capital_only_transition: bool,
) -> Result<(), ProtocolError> {
    if !capital_only_transition {
        return Ok(());
    }
    if successor_reserve < predecessor_reserve {
        return Err(ProtocolError::InsufficientCollateral);
    }
    let before = capital_shortfall_v2(predecessor_reserve, predecessor_deficit_at_current_range)?;
    let after = capital_shortfall_v2(successor_reserve, successor_deficit)?;
    if has_capital_contribution {
        if predecessor_deficit_at_current_range != 0 && after >= before {
            return Err(ProtocolError::InsufficientCollateral);
        }
    } else if after > before {
        // An oracle-only/no-action transition is allowed to reveal a worse
        // authenticated range; it is not a producer-selected capital action.
        return Ok(());
    }
    Ok(())
}

fn order_allows_new_exposure(order: &crate::order::SignedLimitOrder) -> bool {
    !order
        .order
        .flags
        .contains(crate::order::OrderFlags::REDUCE_ONLY)
}

fn verify_v2_deficit_and_mode(witness: &TransitionWitnessV2) -> Result<(), ProtocolError> {
    let accounts = account_map(&witness.base.next_accounts)?;
    let deficit = calculate_next_full_bound_deficit(witness)?;
    let next = witness.next_state.bond;
    if next.full_bound_deficit != deficit
        || next.target_reserve != target_reserve_125(deficit)?
        || next.capital_mode != capital_mode_for(next.insurance_reserve, deficit)?
    {
        return Err(ProtocolError::InvalidBondState);
    }

    let consumed_forced = witness.base.forced_inbox.consumed()?;
    let has_withdrawal = !witness.base.withdrawals.is_empty()
        || consumed_forced
            .iter()
            .any(|entry| matches!(entry.action, crate::forced::ForcedActionV1::Withdraw(_)));
    // A capital-only transition may contain subscriptions and/or non-dilutive
    // recap contributions (or no discretionary action at all). This permits
    // an authenticated oracle-only transition to reveal a newly insolvent
    // portfolio instead of trapping consensus on a stale, apparently-solvent
    // state.  Once an atomic subscription restores the final state to Normal,
    // new exposure is permitted by the final-mode checks below as required by
    // the V2 protocol.
    let capital_only_transition = witness.redemption_enqueues.is_empty()
        && witness.redemption_executions.is_empty()
        && witness.redemption_cancellations.is_empty()
        && witness.base.deposits.is_empty()
        && witness.base.withdrawals.is_empty()
        && witness.base.placements.is_empty()
        && witness.base.cancellations.is_empty()
        && witness.base.fills.is_empty()
        && witness.base.liquidations.is_empty()
        && consumed_forced.is_empty();

    // Full scalar endpoints determine aggregate insurance coverage; they are
    // intentionally not per-position maintenance boundaries. Ordinary state
    // advancement instead fails closed when a final position is unsafe at the
    // current authenticated operational liquidation band. A
    // recapitalization-only transition may carry those positions while the
    // fund is halted, otherwise the authenticated state could neither reveal
    // a new shortfall nor accept subscriptions that repair it.
    verify_operational_position_safety(
        &accounts,
        &witness.base.next_positions,
        witness.base.public.liquidation_low,
        witness.base.public.liquidation_high,
        witness.base.risk_params,
        capital_only_transition && next.capital_mode != CapitalModeV2::Normal,
    )?;

    let has_non_reduce_order = witness
        .base
        .placements
        .iter()
        .any(|placement| order_allows_new_exposure(&placement.order))
        || witness.base.fills.iter().any(|pair| {
            order_allows_new_exposure(&pair.maker_order)
                || order_allows_new_exposure(&pair.taker_order)
        })
        // Liquidation is permitted below the 125% target only when its maker
        // is itself a strictly reduce-only counterparty. Otherwise the target
        // would shed risk by creating new directional exposure in another
        // account, contradicting the proof's 125%-before-new-exposure rule.
        // With no such maker liquidity the transition rejects and safely
        // halts, as required by the V2 insolvency policy.
        || witness
            .base
            .liquidations
            .iter()
            .any(|liquidation| order_allows_new_exposure(&liquidation.maker_order));
    let predecessor_deficit_at_current_range =
        calculate_previous_full_bound_deficit_at_current_range(witness)?;
    let predecessor_mode_at_current_range = capital_mode_for(
        witness.previous_state.bond.insurance_reserve,
        predecessor_deficit_at_current_range,
    )?;
    let has_capital_contribution =
        !witness.subscriptions.is_empty() || !witness.recapitalization_contributions.is_empty();
    verify_capital_only_recovery_progress(
        witness.previous_state.bond.insurance_reserve,
        predecessor_deficit_at_current_range,
        next.insurance_reserve,
        deficit,
        has_capital_contribution,
        capital_only_transition,
    )?;
    let has_other_discretionary_action = !witness.redemption_enqueues.is_empty()
        || !witness.redemption_executions.is_empty()
        || !witness.redemption_cancellations.is_empty()
        || !witness.base.deposits.is_empty()
        || !witness.base.withdrawals.is_empty()
        || !witness.base.placements.is_empty()
        || !witness.base.cancellations.is_empty()
        || !witness.base.fills.is_empty()
        || !witness.base.liquidations.is_empty()
        || !consumed_forced.is_empty();
    verify_recovery_predecessor_permissions(
        predecessor_mode_at_current_range,
        has_capital_contribution,
        next.capital_mode,
        has_other_discretionary_action,
    )?;
    verify_atomic_recapitalization_source(
        predecessor_mode_at_current_range,
        has_capital_contribution,
        has_non_reduce_order,
    )?;
    verify_capital_action_permissions(
        next.capital_mode,
        capital_only_transition,
        has_withdrawal,
        !witness.redemption_enqueues.is_empty(),
        !witness.redemption_executions.is_empty(),
        has_non_reduce_order,
    )
}

fn build_journal(
    witness: &TransitionWitnessV2,
    base: &TransitionJournal,
) -> Result<TransitionJournalV2, ProtocolError> {
    let next = witness.next_state.bond;
    let nav = if next.outstanding_share_atoms == 0 {
        0
    } else {
        nav_per_whole_share_usdd_atoms(next.insurance_reserve, next.outstanding_share_atoms)?
    };
    Ok(TransitionJournalV2 {
        protocol_version: TransitionJournalV2::VERSION,
        configuration_hash: witness.public.configuration_hash,
        parent_mtp: witness.public.parent_mtp,
        oracle_valid_through_mtp: witness.public.oracle_valid_through_mtp,
        authenticated_min_price: witness.public.authenticated_min_price,
        authenticated_max_price: witness.public.authenticated_max_price,
        authenticated_price_range_commitment: witness.public.authenticated_price_range_commitment,
        previous_state_root: witness.public.previous_state_root,
        next_state_root: witness.public.next_state_root,
        previous_sequence: witness.previous_state.sequence(),
        next_sequence: witness.next_state.sequence(),
        bond_action_root: witness.public.bond_action_root,
        order_risk_root: witness.public.order_risk_root,
        funding_state_root: witness.public.funding_state_root,
        matcher_execution_receipt_batch_root: witness.public.matcher_execution_receipt_batch_root,
        previous_matcher_execution_sequence: witness.public.previous_matcher_execution_sequence,
        next_matcher_execution_sequence: witness.public.next_matcher_execution_sequence,
        capital_mode: next.capital_mode,
        insurance_reserve: next.insurance_reserve,
        outstanding_share_atoms: next.outstanding_share_atoms,
        inventory_share_atoms: next.inventory_share_atoms,
        nav_per_whole_share_usdd_atoms: nav,
        full_bound_deficit: next.full_bound_deficit,
        target_reserve: next.target_reserve,
        coverage_bps: coverage_bps(next.insurance_reserve, next.full_bound_deficit)?,
        funding_epoch: witness.next_state.funding.last_parent_mtp / FUNDING_EPOCH_SECONDS,
        redemption_queue_root: next.redemption_queue_root,
        redemption_head: next.redemption_head,
        redemption_tail: next.redemption_tail,
        queued_redemption_share_atoms: next.queued_redemption_share_atoms,
        bond_inbox_head_root: witness.next_state.bond_inbox.head_root,
        bond_inbox_entry_count: witness.next_state.bond_inbox.entry_count,
        bond_inbox_processed_root: witness.next_state.bond_inbox.processed_root,
        bond_inbox_cursor: witness.next_state.bond_inbox.cursor,
        bond_inbox_outcome_root: witness.next_state.bond_inbox_outcome_root,
        bond_inbox_outcome_count: witness.next_state.bond_inbox_outcome_count,
        base_journal_digest: base.digest(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bond::{BOND_FIXED_SUPPLY_ATOMS, BOND_PROTOCOL_VERSION_V2};
    use crate::order::{LimitOrder, OrderFlags, Side, SignedLimitOrder, TimeInForce};
    use crate::risk::RiskParams;
    use crate::transition::LiquidationMatchV1;
    use crate::types::{Quantity, PRICE_SCALE};

    fn bond_state(
        reserve: u128,
        outstanding: u64,
        deficit: u128,
        head: u64,
        tail: u64,
        queued: u64,
        queue_root: Hash32,
    ) -> BondPublicStateV2 {
        BondPublicStateV2 {
            version: BOND_PROTOCOL_VERSION_V2,
            bond_asset_id: [1; 32],
            deployment_commitment: [2; 32],
            inventory_covenant_hash: [3; 32],
            insurance_reserve: reserve,
            issued_share_atoms: BOND_FIXED_SUPPLY_ATOMS,
            outstanding_share_atoms: outstanding,
            inventory_share_atoms: BOND_FIXED_SUPPLY_ATOMS - outstanding,
            full_bound_deficit: deficit,
            target_reserve: target_reserve_125(deficit).unwrap(),
            legacy_fee_pool: 0,
            redemption_queue_root: queue_root,
            redemption_head: head,
            redemption_tail: tail,
            queued_redemption_share_atoms: queued,
            capital_mode: capital_mode_for(reserve, deficit).unwrap(),
        }
    }

    fn entry(sequence: u64, shares: u64) -> RedemptionQueueEntryV2 {
        RedemptionQueueEntryV2::new(
            sequence,
            [sequence as u8 + 10; 32],
            [sequence as u8 + 20; 32],
            [sequence as u8 + 30; 32],
            shares,
            100,
        )
        .unwrap()
    }

    #[test]
    fn queue_validation_accepts_sequence_holes_but_head_is_first_remaining() {
        let queue = vec![entry(7, 10), entry(9, 20)];
        let state = bond_state(1_000, 100, 0, 7, 10, 30, redemption_queue_root_v2(&queue));
        validate_queue(&queue, &state).unwrap();

        let remaining = vec![entry(9, 20)];
        let after = bond_state(
            1_000,
            100,
            0,
            9,
            10,
            20,
            redemption_queue_root_v2(&remaining),
        );
        validate_queue(&remaining, &after).unwrap();
        let mut frozen = after;
        frozen.redemption_head = 8;
        assert_eq!(
            validate_queue(&remaining, &frozen),
            Err(ProtocolError::InvalidBondState)
        );
    }

    #[test]
    fn frozen_queue_bound_is_reachable_and_witness_size_stays_below_sixteen_mib() {
        let maximum = crate::configuration_v2::BOND_REDEMPTION_MAX_QUEUE_ENTRIES_V2;
        assert!(redemption_queue_has_capacity_v2(
            maximum as usize - 1,
            maximum
        ));
        assert!(!redemption_queue_has_capacity_v2(maximum as usize, maximum));

        let entries = (0..u64::from(maximum))
            .map(|sequence| {
                RedemptionQueueEntryV2::new(
                    sequence,
                    tagged_hash("ECX/queue-bound-request-test/v2", &sequence.to_be_bytes()),
                    [21; 32],
                    [31; 32],
                    1,
                    100,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let one_queue_bytes = entries
            .iter()
            .map(|entry| entry.canonical_bytes().len())
            .sum::<usize>();
        assert_eq!(
            one_queue_bytes,
            maximum as usize * RedemptionQueueEntryV2::ENCODED_LEN
        );
        // The transition carries predecessor and successor queues. Even both
        // at the maximum occupy about 1.1 MiB, leaving substantial room under
        // the frozen 16 MiB proof-input ceiling for all other bounded fields.
        assert!(one_queue_bytes * 2 < 2 * 1024 * 1024);
        assert!(one_queue_bytes * 2 < 16 * 1024 * 1024);
    }

    #[test]
    fn recapitalization_contribution_is_signed_non_dilutive_capital() {
        let secret = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let contributor = XOnlyKey(XOnlyPublicKey::from_keypair(&keypair).0.serialize());
        let action = InsuranceRecapitalizationContributionV2 {
            version: InsuranceRecapitalizationContributionV2::VERSION,
            chain_id: [1; 32],
            configuration_hash: [2; 32],
            contributor,
            account_nonce: 7,
            contribution_usdd_atoms: 50_000,
            insurance_output_opening_commitment: [3; 32],
            issued_share_atoms: 0,
            bond_output_opening_commitment: [0; 32],
        };
        let signed =
            SignedInsuranceRecapitalizationContributionV2::sign(action.clone(), &secret).unwrap();
        signed.verify().unwrap();
        let stable = action.contribution_id();
        let full = action.action_id();
        let mut changed_opening = action.clone();
        changed_opening.insurance_output_opening_commitment[0] ^= 1;
        assert_eq!(changed_opening.contribution_id(), stable);
        assert_ne!(changed_opening.action_id(), full);
        let mut dilutive = action;
        dilutive.issued_share_atoms = 1;
        assert_eq!(dilutive.validate(), Err(ProtocolError::InvalidBondState));
    }

    #[test]
    fn malicious_signed_user_semantics_map_to_deterministic_rejections() {
        let trader = XOnlyKey([2; 32]);
        let account = AccountLeaf {
            version: AccountLeaf::VERSION,
            trader,
            account_nonce: 8,
            collateral: Amount(1_000),
            cumulative_realized_pnl: Amount(0),
            salt: [3; 32],
        };
        assert_eq!(
            validate_bond_account_debit_v2(Some(&account), 7, 100),
            Err(BondInboxRejectionV2::InvalidNonce)
        );
        assert_eq!(
            validate_bond_account_debit_v2(Some(&account), 8, 1_001),
            Err(BondInboxRejectionV2::InsufficientCollateral)
        );

        let queue_root = redemption_queue_root_v2(&[]);
        let normal = bond_state(0, 0, 0, 0, 0, 0, queue_root);
        let wrong_quote = BondSubscriptionV2 {
            version: BondSubscriptionV2::VERSION,
            chain_id: [1; 32],
            configuration_hash: [2; 32],
            trader,
            account_nonce: 8,
            contribution_usdd_atoms: 100,
            issued_share_atoms: 99,
            bond_recipient_script_sha256: [4; 32],
            usdd_output_opening_commitment: [5; 32],
            bond_output_opening_commitment: [6; 32],
        };
        assert_eq!(
            validated_subscription_quote_v2(normal, &wrong_quote),
            Err(BondInboxRejectionV2::InvalidSubscriptionQuote)
        );

        let enqueue = RedemptionEnqueueV2 {
            version: RedemptionEnqueueV2::VERSION,
            chain_id: [1; 32],
            configuration_hash: [2; 32],
            claimant: trader,
            account_nonce: 8,
            requested_share_atoms: 1,
            destination_script_hash: [7; 32],
            holder_script_sha256: [8; 32],
            intent_salt: [9; 32],
            refund_script_sha256: [10; 32],
            refund_not_before_parent_height: 112,
            bond_input_opening_commitment: [11; 32],
            queue_output_opening_commitment: [12; 32],
        };
        let recovery = bond_state(50, 100, 100, 0, 0, 0, queue_root);
        assert_eq!(
            validate_enqueue_admission_v2(recovery, 0, 4_096, 100, 12, &enqueue),
            Err(BondInboxRejectionV2::CapitalModeRestriction)
        );
        assert_eq!(
            validate_enqueue_admission_v2(normal, 4_096, 4_096, 100, 12, &enqueue),
            Err(BondInboxRejectionV2::InvalidQueueRequest)
        );

        let nonexistent_cancel = RedemptionCancellationV2Action {
            version: RedemptionCancellationV2Action::VERSION,
            chain_id: [1; 32],
            configuration_hash: [2; 32],
            claimant: trader,
            sequence: 0,
            request_id: [13; 32],
            bond_recipient_script_sha256: [14; 32],
            queue_input_opening_commitment: [15; 32],
            bond_return_output_opening_commitment: [16; 32],
        };
        assert_eq!(
            validated_redemption_cancellation_v2(normal, &[], &nonexistent_cancel),
            Err(BondInboxRejectionV2::InvalidQueueRequest)
        );
    }

    #[test]
    fn authenticated_economic_rejection_consumes_nonce_exactly_once() {
        let trader = XOnlyKey([2; 32]);
        let mut accounts = BTreeMap::from([(
            trader.0,
            AccountLeaf {
                version: AccountLeaf::VERSION,
                trader,
                account_nonce: 8,
                collateral: Amount(1_000),
                cumulative_realized_pnl: Amount(0),
                salt: [3; 32],
            },
        )]);
        let mut effects = V2ExternalEffects::default();
        let reason = BondInboxRejectionV2::InvalidSubscriptionQuote;
        let debit = rejection_nonce_debit_amount_v2(reason).unwrap();
        consume_bond_account_nonce_v2(&mut accounts, &mut effects, trader, 8, debit).unwrap();
        assert_eq!(accounts[&trader.0].account_nonce, 9);
        assert_eq!(accounts[&trader.0].collateral, Amount(1_000));
        assert_eq!(effects.account_debits, vec![(trader, 8, Amount(0))]);
        // A copied rejected request with the same signed nonce cannot later
        // become accepted, and it cannot consume a second nonce.
        assert_eq!(
            validate_bond_account_debit_v2(accounts.get(&trader.0), 8, 0),
            Err(BondInboxRejectionV2::InvalidNonce)
        );
        assert_eq!(
            rejection_nonce_debit_amount_v2(BondInboxRejectionV2::DuplicateOrReplayedAction),
            None
        );
    }

    #[test]
    fn unauthenticated_or_wrong_context_rejection_does_not_consume_nonce() {
        assert_eq!(
            rejection_nonce_debit_amount_v2(BondInboxRejectionV2::MalformedOrInvalidAction),
            None
        );
        assert_eq!(
            rejection_nonce_debit_amount_v2(BondInboxRejectionV2::InvalidContext),
            None
        );
        assert_eq!(
            rejection_nonce_debit_amount_v2(BondInboxRejectionV2::InvalidNonce),
            None
        );
        assert_eq!(
            rejection_nonce_debit_amount_v2(BondInboxRejectionV2::InsufficientCollateral),
            Some(0)
        );
    }

    #[test]
    fn subscription_id_is_stable_but_signature_payload_binds_openings() {
        let mut action = BondSubscriptionV2 {
            version: BondSubscriptionV2::VERSION,
            chain_id: [1; 32],
            configuration_hash: [9; 32],
            trader: XOnlyKey([2; 32]),
            account_nonce: 3,
            contribution_usdd_atoms: 100,
            issued_share_atoms: 100,
            bond_recipient_script_sha256: [4; 32],
            usdd_output_opening_commitment: [1; 32],
            bond_output_opening_commitment: [1; 32],
        };
        action.validate().unwrap();
        let business_id = action.subscription_id();
        let signed_id = action.action_id();
        action.usdd_output_opening_commitment = [5; 32];
        assert_eq!(action.subscription_id(), business_id);
        assert_ne!(action.action_id(), signed_id);
    }

    #[test]
    fn enqueue_request_id_binds_signed_intent_and_node_assigned_metadata() {
        let mut action = RedemptionEnqueueV2 {
            version: RedemptionEnqueueV2::VERSION,
            chain_id: [1; 32],
            configuration_hash: [9; 32],
            claimant: XOnlyKey([2; 32]),
            account_nonce: 7,
            requested_share_atoms: 50,
            destination_script_hash: [3; 32],
            holder_script_sha256: [4; 32],
            intent_salt: [11; 32],
            refund_script_sha256: [10; 32],
            refund_not_before_parent_height: 112,
            bond_input_opening_commitment: [5; 32],
            queue_output_opening_commitment: [6; 32],
        };
        action.validate().unwrap();
        let request_id = action.request_id(7, [8; 32], 100);
        let stable_intent = action.stable_intent_id();
        let action_id = action.action_id();
        action.queue_output_opening_commitment = [7; 32];
        assert_eq!(action.stable_intent_id(), stable_intent);
        assert_eq!(action.request_id(7, [8; 32], 100), request_id);
        assert_ne!(action.action_id(), action_id);
        assert_eq!(
            action.queue_entry(7, [8; 32], 100).unwrap().request_id,
            action.request_id(7, [8; 32], 100)
        );
        assert_ne!(action.request_id(8, [8; 32], 100), request_id);
        assert_ne!(action.request_id(7, [9; 32], 100), request_id);
        assert_ne!(action.request_id(7, [8; 32], 101), request_id);
        action.refund_not_before_parent_height += 1;
        assert_ne!(action.stable_intent_id(), stable_intent);
    }

    #[test]
    fn signed_bond_action_ids_are_bound_to_one_frozen_configuration() {
        let mut subscription = BondSubscriptionV2 {
            version: BondSubscriptionV2::VERSION,
            chain_id: [1; 32],
            configuration_hash: [2; 32],
            trader: XOnlyKey([3; 32]),
            account_nonce: 4,
            contribution_usdd_atoms: 5,
            issued_share_atoms: 5,
            bond_recipient_script_sha256: [6; 32],
            usdd_output_opening_commitment: [7; 32],
            bond_output_opening_commitment: [8; 32],
        };
        let stable = subscription.subscription_id();
        let signed = subscription.action_id();
        subscription.configuration_hash[0] ^= 1;
        assert_ne!(subscription.subscription_id(), stable);
        assert_ne!(subscription.action_id(), signed);
    }

    #[test]
    fn endpoint_deficit_includes_worst_pending_funding_debit() {
        let trader = XOnlyKey([3; 32]);
        let account = AccountLeaf {
            version: AccountLeaf::VERSION,
            trader,
            account_nonce: 0,
            collateral: Amount(0),
            cumulative_realized_pnl: Amount(0),
            salt: [1; 32],
        };
        let position = PositionLeaf {
            version: PositionLeaf::VERSION,
            trader,
            market: crate::ECX_USDD_MARKET,
            position: Position {
                size: 1,
                entry_price: PRICE_SCALE,
                last_funding_index: 0,
            },
            isolated_margin: Amount(0),
            salt: [2; 32],
        };
        let account_binding = [account];
        let accounts = account_map(&account_binding).unwrap();
        let values = endpoint_equities(
            &accounts,
            &[position],
            Price::new(PRICE_SCALE).unwrap(),
            RiskParams::default(),
        )
        .unwrap();
        // One quote unit at the frozen 1% cap, rounded toward safety.
        assert_eq!(values, vec![-1]);
        assert_eq!(full_range_deficit(&values, &values).unwrap(), 1);
    }

    #[test]
    fn current_range_shock_reclassifies_predecessor_before_new_exposure() {
        let trader = XOnlyKey([11; 32]);
        let account = AccountLeaf {
            version: AccountLeaf::VERSION,
            trader,
            account_nonce: 0,
            collateral: Amount(i128::from(20 * PRICE_SCALE)),
            cumulative_realized_pnl: Amount(0),
            salt: [12; 32],
        };
        let position = PositionLeaf {
            version: PositionLeaf::VERSION,
            trader,
            market: crate::ECX_USDD_MARKET,
            position: Position {
                size: i64::try_from(PRICE_SCALE).unwrap(),
                entry_price: 100 * PRICE_SCALE,
                last_funding_index: 0,
            },
            isolated_margin: Amount(0),
            salt: [13; 32],
        };
        let narrow = calculate_full_bound_deficit(
            core::slice::from_ref(&account),
            core::slice::from_ref(&position),
            Price::new(99 * PRICE_SCALE).unwrap(),
            Price::new(101 * PRICE_SCALE).unwrap(),
            RiskParams::default(),
        )
        .unwrap();
        let shocked = calculate_full_bound_deficit(
            &[account],
            &[position],
            Price::new(PRICE_SCALE).unwrap(),
            Price::new(200 * PRICE_SCALE).unwrap(),
            RiskParams::default(),
        )
        .unwrap();
        assert_eq!(narrow, 0);
        assert!(shocked > 0);
        assert_eq!(capital_mode_for(0, narrow).unwrap(), CapitalModeV2::Normal);
        let current_mode = capital_mode_for(0, shocked).unwrap();
        assert_eq!(current_mode, CapitalModeV2::RecapitalizationOnly);
        assert_eq!(
            verify_atomic_recapitalization_source(current_mode, false, true),
            Err(ProtocolError::InsufficientCollateral)
        );
        assert_eq!(
            verify_atomic_recapitalization_source(current_mode, true, true),
            Ok(())
        );
    }

    #[test]
    fn below_one_hundred_percent_is_subscription_only_until_normal() {
        let recovery = CapitalModeV2::RecapitalizationOnly;
        assert_eq!(
            verify_recovery_predecessor_permissions(
                recovery,
                false,
                CapitalModeV2::ReduceOnly,
                true,
            ),
            Err(ProtocolError::InsufficientCollateral)
        );
        assert_eq!(
            verify_recovery_predecessor_permissions(
                recovery,
                true,
                CapitalModeV2::ReduceOnly,
                true,
            ),
            Err(ProtocolError::InsufficientCollateral)
        );
        assert_eq!(
            verify_recovery_predecessor_permissions(recovery, false, CapitalModeV2::Normal, true,),
            Err(ProtocolError::InsufficientCollateral)
        );
        // The one allowed atomic bridge is a proof-bound subscription that
        // restores the final state to the full 125% Normal threshold.
        assert_eq!(
            verify_recovery_predecessor_permissions(recovery, true, CapitalModeV2::Normal, true,),
            Ok(())
        );
        // Oracle/funding-only advancement remains possible while halted.
        assert_eq!(
            verify_recovery_predecessor_permissions(
                recovery,
                false,
                CapitalModeV2::RecapitalizationOnly,
                false,
            ),
            Ok(())
        );
    }

    #[test]
    fn full_range_deficit_can_be_nonzero_while_operational_margin_is_safe() {
        let trader = XOnlyKey([31; 32]);
        let account = AccountLeaf {
            version: AccountLeaf::VERSION,
            trader,
            account_nonce: 0,
            collateral: Amount(i128::from(20 * PRICE_SCALE)),
            cumulative_realized_pnl: Amount(0),
            salt: [32; 32],
        };
        let position = PositionLeaf {
            version: PositionLeaf::VERSION,
            trader,
            market: crate::ECX_USDD_MARKET,
            position: Position {
                size: i64::try_from(PRICE_SCALE).unwrap(),
                entry_price: 100 * PRICE_SCALE,
                last_funding_index: 0,
            },
            isolated_margin: Amount(0),
            salt: [33; 32],
        };
        let account_binding = [account];
        let accounts = account_map(&account_binding).unwrap();
        let low = endpoint_equities(
            &accounts,
            core::slice::from_ref(&position),
            Price::new(PRICE_SCALE).unwrap(),
            RiskParams::default(),
        )
        .unwrap();
        let high = endpoint_equities(
            &accounts,
            core::slice::from_ref(&position),
            Price::new(200 * PRICE_SCALE).unwrap(),
            RiskParams::default(),
        )
        .unwrap();
        let deficit = full_range_deficit(&low, &high).unwrap();
        assert!(deficit > 0);
        let reserve = target_reserve_125(deficit).unwrap();
        assert_eq!(
            capital_mode_for(reserve, deficit).unwrap(),
            CapitalModeV2::Normal
        );
        verify_operational_position_safety(
            &accounts,
            &[position],
            Price::new(99 * PRICE_SCALE).unwrap(),
            Price::new(101 * PRICE_SCALE).unwrap(),
            RiskParams::default(),
            false,
        )
        .unwrap();
    }

    #[test]
    fn unsafe_operational_position_halts_ordinary_but_not_subscription_only_recap() {
        let trader = XOnlyKey([41; 32]);
        let account = AccountLeaf {
            version: AccountLeaf::VERSION,
            trader,
            account_nonce: 0,
            collateral: Amount(i128::from(5 * PRICE_SCALE)),
            cumulative_realized_pnl: Amount(0),
            salt: [42; 32],
        };
        let position = PositionLeaf {
            version: PositionLeaf::VERSION,
            trader,
            market: crate::ECX_USDD_MARKET,
            position: Position {
                size: i64::try_from(PRICE_SCALE).unwrap(),
                entry_price: 100 * PRICE_SCALE,
                last_funding_index: 0,
            },
            isolated_margin: Amount(0),
            salt: [43; 32],
        };
        let account_binding = [account];
        let accounts = account_map(&account_binding).unwrap();
        let ordinary = verify_operational_position_safety(
            &accounts,
            core::slice::from_ref(&position),
            Price::new(99 * PRICE_SCALE).unwrap(),
            Price::new(101 * PRICE_SCALE).unwrap(),
            RiskParams::default(),
            false,
        );
        assert_eq!(ordinary, Err(ProtocolError::InsufficientCollateral));
        verify_operational_position_safety(
            &accounts,
            &[position],
            Price::new(99 * PRICE_SCALE).unwrap(),
            Price::new(101 * PRICE_SCALE).unwrap(),
            RiskParams::default(),
            true,
        )
        .unwrap();
    }

    #[test]
    fn redemption_enqueue_requires_normal_capital_mode() {
        assert_eq!(
            verify_capital_action_permissions(
                CapitalModeV2::ReduceOnly,
                false,
                false,
                true,
                false,
                false,
            ),
            Err(ProtocolError::InsufficientCollateral)
        );
    }

    #[test]
    fn coverage_reducing_withdrawal_and_redemption_execution_require_normal() {
        for mode in [
            CapitalModeV2::ReduceOnly,
            CapitalModeV2::RecapitalizationOnly,
        ] {
            assert_eq!(
                verify_capital_action_permissions(mode, false, true, false, false, false),
                Err(ProtocolError::InsufficientCollateral)
            );
            assert_eq!(
                verify_capital_action_permissions(mode, false, false, false, true, false),
                Err(ProtocolError::InsufficientCollateral)
            );
        }

        assert_eq!(
            verify_capital_action_permissions(
                CapitalModeV2::Normal,
                false,
                true,
                false,
                true,
                false,
            ),
            Ok(())
        );
    }

    #[test]
    fn reduce_only_mode_permits_liquidation_and_cancellation_class_actions() {
        // A liquidation whose maker is separately classified as strictly
        // reduce-only does not set any forbidden flag here. Execution remains
        // fully checked by the base verifier, including both positions,
        // maker margin, and final deficit coverage.
        assert_eq!(
            verify_capital_action_permissions(
                CapitalModeV2::ReduceOnly,
                false,
                false,
                false,
                false,
                false,
            ),
            Ok(())
        );
    }

    #[test]
    fn reduce_only_mode_rejects_liquidator_new_exposure() {
        assert_eq!(
            verify_capital_action_permissions(
                CapitalModeV2::ReduceOnly,
                false,
                false,
                false,
                false,
                true,
            ),
            Err(ProtocolError::InsufficientCollateral)
        );
    }

    #[test]
    fn recapitalization_mode_accepts_only_the_recovery_shape() {
        assert_eq!(
            verify_capital_action_permissions(
                CapitalModeV2::RecapitalizationOnly,
                true,
                false,
                false,
                false,
                false,
            ),
            Ok(())
        );
        assert_eq!(
            verify_capital_action_permissions(
                CapitalModeV2::RecapitalizationOnly,
                false,
                false,
                false,
                false,
                false,
            ),
            Err(ProtocolError::InvalidBondState)
        );
    }

    #[test]
    fn atomic_recapitalization_can_restore_normal_and_add_exposure() {
        assert_eq!(
            verify_atomic_recapitalization_source(CapitalModeV2::RecapitalizationOnly, true, true,),
            Ok(())
        );
        assert_eq!(
            verify_capital_action_permissions(
                CapitalModeV2::Normal,
                false,
                false,
                false,
                false,
                true,
            ),
            Ok(())
        );
    }

    #[test]
    fn repeated_partial_capital_only_recovery_makes_strict_progress() {
        // 50/100 remains below 100%; the first non-dilutive contribution
        // raises it to 60/100 and is valid even though recovery is incomplete.
        verify_capital_only_recovery_progress(50, 100, 60, 100, true, true).unwrap();
        // A second transition may cross into ReduceOnly (110% but below the
        // 125% target) without requiring a one-shot restoration to Normal.
        verify_capital_only_recovery_progress(60, 100, 110, 100, true, true).unwrap();
        // And a later transition can finish the recovery.
        verify_capital_only_recovery_progress(110, 100, 125, 100, true, true).unwrap();
    }

    #[test]
    fn capital_only_recovery_rejects_no_progress_or_reserve_decrease() {
        assert_eq!(
            verify_capital_only_recovery_progress(50, 100, 60, 110, true, true),
            Err(ProtocolError::InsufficientCollateral)
        );
        assert_eq!(
            verify_capital_only_recovery_progress(50, 100, 49, 100, false, true),
            Err(ProtocolError::InsufficientCollateral)
        );
        // Oracle-only advancement may reveal a wider authenticated range and
        // a larger shortfall, provided reserve was not spent.
        verify_capital_only_recovery_progress(50, 100, 50, 120, false, true).unwrap();
        // The recovery-progress rule is not a substitute for ordinary action
        // permissions on a transition that contains other actions.
        verify_capital_only_recovery_progress(50, 100, 40, 120, true, false).unwrap();
    }

    #[test]
    fn non_normal_state_cannot_self_bootstrap_new_exposure_without_subscription() {
        for mode in [
            CapitalModeV2::ReduceOnly,
            CapitalModeV2::RecapitalizationOnly,
        ] {
            assert_eq!(
                verify_atomic_recapitalization_source(mode, false, true),
                Err(ProtocolError::InsufficientCollateral)
            );
            assert_eq!(
                verify_atomic_recapitalization_source(mode, false, false),
                Ok(())
            );
        }
    }

    #[test]
    fn partial_redemption_requires_exact_remainder_output_opening() {
        assert_eq!(verify_remainder_opening_commitment(0, [0; 32]), Ok(()));
        assert_eq!(verify_remainder_opening_commitment(1, [7; 32]), Ok(()));
        assert_eq!(
            verify_remainder_opening_commitment(1, [0; 32]),
            Err(ProtocolError::InvalidBondState)
        );
        assert_eq!(
            verify_remainder_opening_commitment(0, [7; 32]),
            Err(ProtocolError::InvalidBondState)
        );
    }

    #[test]
    fn one_transition_cannot_execute_the_same_fifo_request_twice() {
        let request = [71; 32];
        let mut executed = BTreeSet::new();
        assert!(executed.insert(request));
        assert!(!executed.insert(request));
    }

    #[test]
    fn stable_settlement_ids_are_unique_even_when_full_openings_differ() {
        let id = [72; 32];
        let mut ids = BTreeSet::new();
        assert!(ids.insert(id));
        assert!(!ids.insert(id));
    }

    #[test]
    fn cancellation_settlement_id_is_non_circular_but_signature_binds_openings() {
        let action = RedemptionCancellationV2Action {
            version: RedemptionCancellationV2Action::VERSION,
            chain_id: [61; 32],
            configuration_hash: [60; 32],
            claimant: XOnlyKey([62; 32]),
            sequence: 7,
            request_id: [63; 32],
            bond_recipient_script_sha256: [64; 32],
            queue_input_opening_commitment: [65; 32],
            bond_return_output_opening_commitment: [66; 32],
        };
        let stable = action.cancellation_id();
        let full = action.action_id();
        let mut changed_opening = action;
        changed_opening.bond_return_output_opening_commitment = [67; 32];
        assert_eq!(changed_opening.cancellation_id(), stable);
        assert_ne!(changed_opening.action_id(), full);
    }

    #[test]
    fn epoch_start_open_interest_uses_carried_boundary_mark() {
        let position = PositionLeaf {
            version: PositionLeaf::VERSION,
            trader: XOnlyKey([51; 32]),
            market: crate::ECX_USDD_MARKET,
            position: Position {
                size: i64::try_from(PRICE_SCALE).unwrap(),
                entry_price: 100 * PRICE_SCALE,
                last_funding_index: 0,
            },
            isolated_margin: Amount(0),
            salt: [52; 32],
        };
        let at_boundary = open_interest_notional_at_mark(
            core::slice::from_ref(&position),
            Price::new(100 * PRICE_SCALE).unwrap(),
        )
        .unwrap();
        let post_boundary =
            open_interest_notional_at_mark(&[position], Price::new(200 * PRICE_SCALE).unwrap())
                .unwrap();
        assert_eq!(at_boundary, u128::from(100 * PRICE_SCALE));
        assert_eq!(post_boundary, 2 * at_boundary);
    }

    #[test]
    fn canonical_risk_roots_reject_duplicate_keys() {
        let commitment = OrderRiskCommitmentV2 {
            version: OrderRiskCommitmentV2::VERSION,
            configuration_hash: [6; 32],
            order_id: [7; 32],
            trader: XOnlyKey([8; 32]),
            selected_initial_margin_bps: 1_000,
            signature: Signature64([9; 64]),
        };
        assert_eq!(
            active_order_risk_root_v2(&[commitment.clone(), commitment]),
            Err(ProtocolError::DuplicateMerkleKey)
        );
    }

    #[test]
    fn resting_order_cannot_swap_its_signed_margin_selection_at_fill() {
        let resting = OrderRiskCommitmentV2 {
            version: OrderRiskCommitmentV2::VERSION,
            configuration_hash: [6; 32],
            order_id: [7; 32],
            trader: XOnlyKey([8; 32]),
            selected_initial_margin_bps: 5_000,
            signature: Signature64([9; 64]),
        };
        let mut replacement = resting.clone();
        replacement.selected_initial_margin_bps = 1_000;
        replacement.signature = Signature64([10; 64]);

        let previous = BTreeMap::from([(resting.order_id, &resting)]);
        let exact = BTreeMap::from([(resting.order_id, &resting)]);
        let substituted = BTreeMap::from([(replacement.order_id, &replacement)]);
        assert_eq!(
            verify_resting_order_risk_immutability(&previous, &exact),
            Ok(())
        );
        assert_eq!(
            verify_resting_order_risk_immutability(&previous, &substituted),
            Err(ProtocolError::InvalidBondState)
        );
    }

    #[test]
    fn direction_crossing_is_treated_as_new_risk() {
        let old = Position {
            size: 10,
            entry_price: PRICE_SCALE,
            last_funding_index: 0,
        };
        let crossed = crate::risk::apply_fill(
            old,
            crate::order::Side::Sell,
            Quantity::new(15).unwrap(),
            Price::new(PRICE_SCALE).unwrap(),
        )
        .unwrap()
        .position;
        assert_eq!(crossed.size, -5);
        assert!(creates_directional_risk(old, crossed));
    }

    #[test]
    fn liquidation_execution_is_a_funding_observation() {
        let executed_price = Price::new(123 * PRICE_SCALE).unwrap();
        let executed_quantity = Quantity::new(4).unwrap();
        let liquidation = LiquidationMatchV1 {
            target: XOnlyKey([3; 32]),
            maker_order: SignedLimitOrder {
                order: LimitOrder {
                    version: LimitOrder::VERSION,
                    chain_id: [1; 32],
                    market: crate::ECX_USDD_MARKET,
                    trader: XOnlyKey([2; 32]),
                    side: Side::Sell,
                    time_in_force: TimeInForce::GoodTilHeight,
                    flags: OrderFlags::NONE,
                    limit_price: executed_price,
                    quantity: executed_quantity,
                    client_order_id: [4; 16],
                    max_fee_bps: 5,
                    nonce: 1,
                    valid_from_height: 0,
                    expires_at_height: u64::MAX,
                },
                signature: Signature64([0; 64]),
            },
            quantity: executed_quantity,
        };
        assert!(order_allows_new_exposure(&liquidation.maker_order));
        let mut reduce_only_liquidator = liquidation.clone();
        reduce_only_liquidator.maker_order.order.flags = OrderFlags::REDUCE_ONLY;
        assert!(!order_allows_new_exposure(
            &reduce_only_liquidator.maker_order
        ));
        let parent_mtp = 99;
        let observation = liquidation_funding_observation_v2(&liquidation, parent_mtp).unwrap();
        assert_eq!(
            observation,
            TimestampedFundingObservationV2 {
                price: executed_price,
                quantity: executed_quantity,
                execution_parent_mtp: parent_mtp,
            }
        );
    }

    #[test]
    fn execution_requires_exact_authenticated_prior_parent_context() {
        assert_eq!(
            verify_execution_context_values_v2(20, 21, 1_000, 50_000, 20, 1_000, 50_000),
            Ok(())
        );
        assert_eq!(
            verify_execution_context_values_v2(20, 21, 1_000, 50_000, 19, 1_000, 50_000),
            Err(ProtocolError::InvalidMatcherReceipt)
        );
        assert_eq!(
            verify_execution_context_values_v2(20, 21, 1_000, 50_000, 20, 999, 49_999),
            Err(ProtocolError::InvalidMatcherReceipt)
        );
        assert_eq!(
            verify_execution_context_values_v2(20, 21, 1_000, 50_000, 20, 1_000, 49_999),
            Err(ProtocolError::InvalidMatcherReceipt)
        );
    }
}
