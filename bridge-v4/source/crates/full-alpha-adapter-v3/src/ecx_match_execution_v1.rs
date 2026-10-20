//! ECX match composition through actual native execution, not a legacy capital carry.
//! The receipt consumer must pin the native source binding and ECX checkpoint.
use crate::child_execution_guest_v3::{AlphaChildExecutionInputV3, AlphaChildExecutionErrorV3};
use crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV2;
use ecx_proof_core::{ecx_successor_state_v1::EcxSuccessorStateV1,
    ecx_execution_v1::EcxTradingVaultWitnessV1, proof_v2::ProofErrorV2};
use bincode::Options;
use serde::{Serialize, Deserialize};
pub use ecx_proof_core::ecx_match_input_v1::{ConsensusProofVerifier, ConsensusProofVerificationError};

/// Owned host/guest transport. Pins are public claims, not trust roots: the
/// receipt consumer must independently select and check them in ECXNJ1.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedEcxNativeMatchV1 {
    pub execution: AlphaChildExecutionInputV3,
    pub binding: crate::child_execution_statement_v4::AlphaChildExecutionBindingV5,
    pub native_checkpoint: crate::child_execution_state_v4::ChildExecutionCheckpointV5,
    pub deposit_policy: crate::native_deposit_policy_v4::AlphaDepositPolicyV4,
    pub environment: Vec<u8>,
    pub native_binding_pin: crate::Hash32,
    pub checkpoint_pin: crate::Hash32,
    pub checkpoint: EcxMatchCheckpointV2,
    pub transaction_index: u32,
    pub state_bytes: Vec<u8>,
    pub bindings: ecx_protocol_core::ecx_configuration_v1::EcxSuccessorBindingsV1,
    pub economics: ecx_protocol_core::ecx_configuration_v1::EcxConfigurationV1,
    pub journal: Vec<u8>,
    pub proof: Vec<u8>,
    pub source_transaction: Vec<u8>,
    pub successor_transaction: Vec<u8>,
    pub successor_vout: u32,
    pub successor_script_sha256: crate::Hash32,
    pub prior_accounts: Vec<(ecx_protocol_core::TraderLeafV2, Vec<u8>)>,
    pub successor_accounts: Vec<(ecx_protocol_core::TraderLeafV2, Vec<u8>)>,
    #[serde(with = "coin_transport")]
    pub coin: ecx_full_consensus_validator_v2::elements_v2::ElementsUtxoLeafV2,
    pub path: ecx_full_consensus_validator_v2::elements_v2::ElementsSparseUtxoPathV2,
    #[serde(with = "coin_transport")]
    pub successor_coin: ecx_full_consensus_validator_v2::elements_v2::ElementsUtxoLeafV2,
    pub successor_path: ecx_full_consensus_validator_v2::elements_v2::ElementsSparseUtxoPathV2,
}

/// TxOut's serde visitor is not bincode-compatible. Use consensus codecs,
/// retaining its separately encoded witness (including range/surjection proofs).
mod coin_transport {
    use super::*;
    use ecx_full_consensus_validator_v2::elements_v2::ElementsUtxoLeafV2;
    pub fn serialize<S: serde::Serializer>(coin: &ElementsUtxoLeafV2, serializer: S)
        -> Result<S::Ok, S::Error> {
        (coin.outpoint, elements::encode::serialize(&coin.output),
            elements::encode::serialize(&coin.output.witness), coin.creation_height,
            coin.creation_parent_mtp, coin.coinbase, coin.created_by_issuance,
            coin.created_by_pegin).serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(deserializer: D)
        -> Result<ElementsUtxoLeafV2, D::Error> {
        let (outpoint, output, witness, creation_height, creation_parent_mtp,
            coinbase, created_by_issuance, created_by_pegin):
            (elements::OutPoint, Vec<u8>, Vec<u8>, u32, u32, bool, bool, bool) =
            Deserialize::deserialize(deserializer)?;
        let mut output: elements::TxOut = elements::encode::deserialize(&output)
            .map_err(serde::de::Error::custom)?;
        output.witness = elements::encode::deserialize(&witness).map_err(serde::de::Error::custom)?;
        Ok(ElementsUtxoLeafV2 { outpoint, output, creation_height, creation_parent_mtp,
            coinbase, created_by_issuance, created_by_pegin })
    }
}

pub const MAX_ECX_NATIVE_INPUT_BYTES: usize = 128 * 1024 * 1024;

/// Cancellation's actual native witness, not a substituted match/withdrawal.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedEcxNativeCancellationV1 {
    pub execution: AlphaChildExecutionInputV3,
    pub binding: crate::child_execution_statement_v4::AlphaChildExecutionBindingV5,
    pub native_checkpoint: crate::child_execution_state_v4::ChildExecutionCheckpointV5,
    pub deposit_policy: crate::native_deposit_policy_v4::AlphaDepositPolicyV4,
    pub environment: Vec<u8>,
    pub native_binding_pin: crate::Hash32,
    pub checkpoint_pin: crate::Hash32,
    pub checkpoint: EcxMatchCheckpointV2,
    pub transaction_index: u32,
    pub state_bytes: Vec<u8>,
    pub cancellation: ecx_proof_core::ecx_cancellation_input_v1::EcxCancellationInputV1,
    #[serde(with = "coin_transport")]
    pub coin: ecx_full_consensus_validator_v2::elements_v2::ElementsUtxoLeafV2,
    pub path: ecx_full_consensus_validator_v2::elements_v2::ElementsSparseUtxoPathV2,
    #[serde(with = "coin_transport")]
    pub successor_coin: ecx_full_consensus_validator_v2::elements_v2::ElementsUtxoLeafV2,
    pub successor_path: ecx_full_consensus_validator_v2::elements_v2::ElementsSparseUtxoPathV2,
}

impl OwnedEcxNativeCancellationV1 {
    /// Native execution only. The envelope must authenticate its predecessor.
    pub fn execute<P, S>(&self, parent: &P, simplicity: &S)
        -> Result<ExecutedEcxNativeMatchV1, EcxMatchExecutionErrorV1>
    where P: crate::FullAlphaReceiptVerifierV3,
        S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2,
    {
        use EcxMatchExecutionErrorV1::{Native, Match};
        use crate::ecx_deposit_membership_v1::EcxCoinMembershipV1;
        let invalid = || Native(AlphaChildExecutionErrorV3::Binding);
        if self.native_binding_pin == [0;32]
            || self.binding.commitment().map_err(Native)? != self.native_binding_pin
            || self.checkpoint.native_projection(self.checkpoint_pin).map_err(|_| invalid())?
                != self.native_checkpoint
        { return Err(invalid()); }
        let prior = EcxSuccessorStateV1::decode(&self.state_bytes).map_err(Match)?;
        let environment = crate::ecx_environment_v4::EcxExecutionEnvironmentV1::decode(
            &self.environment).map_err(|_| invalid())?;
        let (checked, context) = crate::child_execution_guest_v4::execute_alpha_child_native_v5(
            &self.execution, &self.binding, &self.native_checkpoint, &self.deposit_policy,
            &environment, parent, simplicity).map_err(Native)?;
        let inner_pin = self.checkpoint.state.commitment().map_err(|_| invalid())?;
        let (state, next) = context.advance_ecx_owned_cancellation(&checked,
            self.transaction_index as usize, &self.checkpoint.state, inner_pin, &prior,
            &self.cancellation, EcxCoinMembershipV1 { leaf: &self.coin, path: &self.path },
            EcxCoinMembershipV1 { leaf: &self.successor_coin, path: &self.successor_path })
            .map_err(Match)?;
        let (statement, endpoint) = crate::conversion_parent_link_v3::authenticate_alpha_bmm_endpoint_v4(
            &self.execution.parent, self.binding.execution.parent_binding, parent)
            .map_err(|_| invalid())?;
        if &statement != checked.parent() { return Err(invalid()); }
        let next = EcxMatchCheckpointV2 { state: next, bmm_endpoint: Some(endpoint.to_vec()) };
        let public_values = EcxNativeMatchPublicValuesV1 {
            native_binding: self.native_binding_pin, predecessor_checkpoint: self.checkpoint_pin,
            successor_checkpoint: next.commitment().map_err(|_| invalid())?, state,
        };
        public_values.check_opening(self.native_binding_pin, self.checkpoint_pin, &next).map_err(Match)?;
        let journal = public_values.canonical_bytes().map_err(Match)?;
        Ok(ExecutedEcxNativeMatchV1 { public_values, checkpoint: next, journal })
    }
}

/// Admission's actual native witness, not a substituted match/withdrawal.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedEcxNativeAdmissionV1 {
    pub execution: AlphaChildExecutionInputV3,
    pub binding: crate::child_execution_statement_v4::AlphaChildExecutionBindingV5,
    pub native_checkpoint: crate::child_execution_state_v4::ChildExecutionCheckpointV5,
    pub deposit_policy: crate::native_deposit_policy_v4::AlphaDepositPolicyV4,
    pub environment: Vec<u8>,
    pub native_binding_pin: crate::Hash32,
    pub checkpoint_pin: crate::Hash32,
    pub checkpoint: EcxMatchCheckpointV2,
    pub transaction_index: u32,
    pub state_bytes: Vec<u8>,
    pub admission: ecx_proof_core::ecx_admission_input_v1::EcxAdmissionInputV1,
    #[serde(with = "coin_transport")]
    pub coin: ecx_full_consensus_validator_v2::elements_v2::ElementsUtxoLeafV2,
    pub path: ecx_full_consensus_validator_v2::elements_v2::ElementsSparseUtxoPathV2,
    #[serde(with = "coin_transport")]
    pub successor_coin: ecx_full_consensus_validator_v2::elements_v2::ElementsUtxoLeafV2,
    pub successor_path: ecx_full_consensus_validator_v2::elements_v2::ElementsSparseUtxoPathV2,
}

impl OwnedEcxNativeAdmissionV1 {
    /// Native execution only. The envelope must authenticate its predecessor.
    pub fn execute<P, S, V>(&self, parent: &P, simplicity: &S, verifier: &V)
        -> Result<ExecutedEcxNativeMatchV1, EcxMatchExecutionErrorV1>
    where P: crate::FullAlphaReceiptVerifierV3,
        S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2,
        V: ConsensusProofVerifier,
    {
        use EcxMatchExecutionErrorV1::{Native, Match};
        use crate::ecx_deposit_membership_v1::EcxCoinMembershipV1;
        let invalid = || Native(AlphaChildExecutionErrorV3::Binding);
        if self.native_binding_pin == [0;32]
            || self.binding.commitment().map_err(Native)? != self.native_binding_pin
            || self.checkpoint.native_projection(self.checkpoint_pin).map_err(|_| invalid())?
                != self.native_checkpoint
        { return Err(invalid()); }
        let prior = EcxSuccessorStateV1::decode(&self.state_bytes).map_err(Match)?;
        let environment = crate::ecx_environment_v4::EcxExecutionEnvironmentV1::decode(
            &self.environment).map_err(|_| invalid())?;
        let (checked, context) = crate::child_execution_guest_v4::execute_alpha_child_native_v5(
            &self.execution, &self.binding, &self.native_checkpoint, &self.deposit_policy,
            &environment, parent, simplicity).map_err(Native)?;
        let inner_pin = self.checkpoint.state.commitment().map_err(|_| invalid())?;
        let (state, _funding, next) = context.advance_ecx_owned_admission(&checked,
            self.transaction_index as usize, &self.checkpoint.state, inner_pin, &prior,
            &self.admission, EcxCoinMembershipV1 { leaf: &self.coin, path: &self.path },
            EcxCoinMembershipV1 { leaf: &self.successor_coin, path: &self.successor_path }, verifier)
            .map_err(Match)?;
        let (statement, endpoint) = crate::conversion_parent_link_v3::authenticate_alpha_bmm_endpoint_v4(
            &self.execution.parent, self.binding.execution.parent_binding, parent)
            .map_err(|_| invalid())?;
        if &statement != checked.parent() { return Err(invalid()); }
        let next = EcxMatchCheckpointV2 { state: next, bmm_endpoint: Some(endpoint.to_vec()) };
        let public_values = EcxNativeMatchPublicValuesV1 {
            native_binding: self.native_binding_pin, predecessor_checkpoint: self.checkpoint_pin,
            successor_checkpoint: next.commitment().map_err(|_| invalid())?, state,
        };
        public_values.check_opening(self.native_binding_pin, self.checkpoint_pin, &next).map_err(Match)?;
        let journal = public_values.canonical_bytes().map_err(Match)?;
        Ok(ExecutedEcxNativeMatchV1 { public_values, checkpoint: next, journal })
    }
}

/// Liquidation's actual native witness, not a substituted match/withdrawal.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedEcxNativeLiquidationV1 {
    pub execution: AlphaChildExecutionInputV3,
    pub binding: crate::child_execution_statement_v4::AlphaChildExecutionBindingV5,
    pub native_checkpoint: crate::child_execution_state_v4::ChildExecutionCheckpointV5,
    pub deposit_policy: crate::native_deposit_policy_v4::AlphaDepositPolicyV4,
    pub environment: Vec<u8>,
    pub native_binding_pin: crate::Hash32,
    pub checkpoint_pin: crate::Hash32,
    pub checkpoint: EcxMatchCheckpointV2,
    pub transaction_index: u32,
    pub state_bytes: Vec<u8>,
    pub liquidation: ecx_proof_core::ecx_liquidation_input_v1::EcxLiquidationInputV1,
    #[serde(with = "coin_transport")]
    pub coin: ecx_full_consensus_validator_v2::elements_v2::ElementsUtxoLeafV2,
    pub path: ecx_full_consensus_validator_v2::elements_v2::ElementsSparseUtxoPathV2,
    #[serde(with = "coin_transport")]
    pub successor_coin: ecx_full_consensus_validator_v2::elements_v2::ElementsUtxoLeafV2,
    pub successor_path: ecx_full_consensus_validator_v2::elements_v2::ElementsSparseUtxoPathV2,
}

impl OwnedEcxNativeLiquidationV1 {
    /// Native execution only. The envelope must authenticate its predecessor.
    pub fn execute<P, S, V>(&self, parent: &P, simplicity: &S, verifier: &V)
        -> Result<ExecutedEcxNativeMatchV1, EcxMatchExecutionErrorV1>
    where P: crate::FullAlphaReceiptVerifierV3,
        S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2,
        V: ConsensusProofVerifier,
    {
        use EcxMatchExecutionErrorV1::{Native, Match};
        use crate::ecx_deposit_membership_v1::EcxCoinMembershipV1;
        let invalid = || Native(AlphaChildExecutionErrorV3::Binding);
        if self.native_binding_pin == [0;32]
            || self.binding.commitment().map_err(Native)? != self.native_binding_pin
            || self.checkpoint.native_projection(self.checkpoint_pin).map_err(|_| invalid())?
                != self.native_checkpoint
        { return Err(invalid()); }
        let prior = EcxSuccessorStateV1::decode(&self.state_bytes).map_err(Match)?;
        let environment = crate::ecx_environment_v4::EcxExecutionEnvironmentV1::decode(
            &self.environment).map_err(|_| invalid())?;
        let (checked, context) = crate::child_execution_guest_v4::execute_alpha_child_native_v5(
            &self.execution, &self.binding, &self.native_checkpoint, &self.deposit_policy,
            &environment, parent, simplicity).map_err(Native)?;
        let inner_pin = self.checkpoint.state.commitment().map_err(|_| invalid())?;
        let (state, _funding, next) = context.advance_ecx_owned_liquidation(&checked,
            self.transaction_index as usize, &self.checkpoint.state, inner_pin, &prior,
            &self.liquidation, EcxCoinMembershipV1 { leaf: &self.coin, path: &self.path },
            EcxCoinMembershipV1 { leaf: &self.successor_coin, path: &self.successor_path }, verifier)
            .map_err(Match)?;
        let (statement, endpoint) = crate::conversion_parent_link_v3::authenticate_alpha_bmm_endpoint_v4(
            &self.execution.parent, self.binding.execution.parent_binding, parent)
            .map_err(|_| invalid())?;
        if &statement != checked.parent() { return Err(invalid()); }
        let next = EcxMatchCheckpointV2 { state: next, bmm_endpoint: Some(endpoint.to_vec()) };
        let public_values = EcxNativeMatchPublicValuesV1 {
            native_binding: self.native_binding_pin, predecessor_checkpoint: self.checkpoint_pin,
            successor_checkpoint: next.commitment().map_err(|_| invalid())?, state,
        };
        public_values.check_opening(self.native_binding_pin, self.checkpoint_pin, &next).map_err(Match)?;
        let journal = public_values.canonical_bytes().map_err(Match)?;
        Ok(ExecutedEcxNativeMatchV1 { public_values, checkpoint: next, journal })
    }
}

/// Borrowed opening shared by match and withdrawal recursion. No operation
/// payload is substituted: these references must come from the executed input.
struct EcxContinuationOpening<'a> {
    binding: &'a crate::child_execution_statement_v4::AlphaChildExecutionBindingV5,
    environment: &'a [u8],
    parent: &'a crate::conversion_parent_link_v3::AlphaConversionLinkBindingV3,
    checkpoint: &'a EcxMatchCheckpointV2,
    checkpoint_pin: crate::Hash32,
    native_checkpoint: &'a crate::child_execution_state_v4::ChildExecutionCheckpointV5,
    state_bytes: &'a [u8],
}

/// Versioned withdrawal transport, distinct from match inputs. Decoding does
/// not authenticate a predecessor or select an outstanding-order risk policy.
/// Those remain obligations of the enclosing continuation guest.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedEcxNativeWithdrawalV1 {
    pub execution: AlphaChildExecutionInputV3,
    pub binding: crate::child_execution_statement_v4::AlphaChildExecutionBindingV5,
    pub native_checkpoint: crate::child_execution_state_v4::ChildExecutionCheckpointV5,
    pub deposit_policy: crate::native_deposit_policy_v4::AlphaDepositPolicyV4,
    pub environment: Vec<u8>,
    pub native_binding_pin: crate::Hash32,
    pub checkpoint_pin: crate::Hash32,
    pub checkpoint: EcxMatchCheckpointV2,
    pub transaction_index: u32,
    pub state_bytes: Vec<u8>,
    pub withdrawal: ecx_proof_core::ecx_withdrawal_input_v1::EcxWithdrawalInputV1,
    #[serde(with = "coin_transport")]
    pub coin: ecx_full_consensus_validator_v2::elements_v2::ElementsUtxoLeafV2,
    pub path: ecx_full_consensus_validator_v2::elements_v2::ElementsSparseUtxoPathV2,
    #[serde(with = "coin_transport")]
    pub successor_coin: ecx_full_consensus_validator_v2::elements_v2::ElementsUtxoLeafV2,
    pub successor_path: ecx_full_consensus_validator_v2::elements_v2::ElementsSparseUtxoPathV2,
}

impl OwnedEcxNativeWithdrawalV1 {
    /// Authenticate an initialization receipt opening. This does not replace
    /// recursive origin-policy continuity checks or withdrawal risk policy.
    pub fn verify_predecessor_receipt<V: ConsensusProofVerifier>(
        &self, journal: &[u8], proof: &[u8], verifier: &V,
        expected_program: crate::Hash32, expected_binding: crate::Hash32,
        expected_predecessor: crate::Hash32,
    ) -> Result<(), EcxMatchExecutionErrorV1> {
        verify_native_predecessor_opening(journal, proof, verifier, expected_program,
            expected_binding, expected_predecessor, &self.checkpoint,
            self.checkpoint_pin, &self.native_checkpoint, &self.state_bytes)
    }

    pub fn encode(&self) -> Result<Vec<u8>, EcxMatchExecutionErrorV1> {
        let payload = bincode::DefaultOptions::new().with_fixint_encoding()
            .with_limit((MAX_ECX_NATIVE_INPUT_BYTES - 6) as u64)
            .serialize(self).map_err(|_| OwnedEcxNativeMatchV1::invalid())?;
        let mut bytes = b"ECXNW1".to_vec();
        bytes.extend(payload);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, EcxMatchExecutionErrorV1> {
        if bytes.len() < 6 || bytes.len() > MAX_ECX_NATIVE_INPUT_BYTES || &bytes[..6] != b"ECXNW1" {
            return Err(OwnedEcxNativeMatchV1::invalid());
        }
        bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes()
            .with_limit((MAX_ECX_NATIVE_INPUT_BYTES - 6) as u64)
            .deserialize(&bytes[6..]).map_err(|_| OwnedEcxNativeMatchV1::invalid())
    }

    /// Execute the native relation only; this is not recursive acceptance.
    pub fn execute<P, S, V>(&self, parent: &P, simplicity: &S, verifier: &V)
        -> Result<ExecutedEcxNativeMatchV1, EcxMatchExecutionErrorV1>
    where P: crate::FullAlphaReceiptVerifierV3,
        S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2,
        V: ConsensusProofVerifier,
    {
        use crate::ecx_deposit_membership_v1::EcxCoinMembershipV1;
        let prior = EcxSuccessorStateV1::decode(&self.state_bytes)
            .map_err(EcxMatchExecutionErrorV1::Match)?;
        let environment = crate::ecx_environment_v4::EcxExecutionEnvironmentV1::decode(&self.environment)
            .map_err(|_| OwnedEcxNativeMatchV1::invalid())?;
        execute_alpha_ecx_withdrawal_v1(&self.execution, &self.binding, &self.native_checkpoint,
            &self.deposit_policy, &environment, self.native_binding_pin, self.checkpoint_pin,
            &self.checkpoint, &prior, self.transaction_index as usize, &self.withdrawal,
            EcxCoinMembershipV1 { leaf: &self.coin, path: &self.path },
            EcxCoinMembershipV1 { leaf: &self.successor_coin, path: &self.successor_path },
            parent, simplicity, verifier)
    }
}

/// Recursive continuation transport, deliberately distinct from frozen initialization.
/// ECXCI2/ECXNC2 supersede the undeployed one-step V1 wire formats. All four
/// origin/recursive pins are public claims: consumers MUST independently
/// select them, never trust values chosen by a prover.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedEcxContinuationEnvelopeV1<T> {
    pub input: T,
    /// Independently selected recursive guest role, exposed in every receipt.
    pub continuation_program: crate::Hash32,
    /// False consumes initialization ECXNJ1; true consumes recursive ECXNC2.
    pub recursive: bool,
    pub initialization_binding: crate::child_execution_statement_v4::AlphaChildExecutionBindingV5,
    pub initialization_parent: crate::conversion_parent_link_v3::AlphaConversionLinkBindingV3,
    pub initialization_environment: Vec<u8>,
    pub predecessor_program: crate::Hash32,
    pub predecessor_binding: crate::Hash32,
    pub predecessor_checkpoint: crate::Hash32,
    pub predecessor_journal: Vec<u8>,
    pub predecessor_proof: Vec<u8>,
}

/// Preserve the existing match wire format and callers. The generic envelope
/// shares authentication metadata, never substitutes one operation's payload
/// for another, and does not itself implement guest execution.
pub type OwnedEcxNativeContinuationV1 = OwnedEcxContinuationEnvelopeV1<OwnedEcxNativeMatchV1>;
pub type OwnedEcxWithdrawalContinuationV1 = OwnedEcxContinuationEnvelopeV1<OwnedEcxNativeWithdrawalV1>;
pub type OwnedEcxCancellationContinuationV1 = OwnedEcxContinuationEnvelopeV1<OwnedEcxNativeCancellationV1>;
pub type OwnedEcxAdmissionContinuationV1 = OwnedEcxContinuationEnvelopeV1<OwnedEcxNativeAdmissionV1>;

/// Explicit operation dispatch shared by host and guest. No fallback decoder:
/// each versioned prefix selects exactly one authenticated action relation.
pub enum OwnedEcxContinuationActionV1 {
    Liquidation(Box<OwnedEcxLiquidationContinuationV1>),
    Admission(Box<OwnedEcxAdmissionContinuationV1>),
    Match(Box<OwnedEcxNativeContinuationV1>),
    Withdrawal(Box<OwnedEcxWithdrawalContinuationV1>),
    Cancellation(Box<OwnedEcxCancellationContinuationV1>),
}

impl OwnedEcxContinuationActionV1 {
    pub fn decode(bytes: &[u8]) -> Result<Self, EcxMatchExecutionErrorV1> {
        match bytes.get(..6) {
            Some(b"ECXLI1") => OwnedEcxLiquidationContinuationV1::decode(bytes)
                .map(|input| Self::Liquidation(Box::new(input))),
            Some(b"ECXOI1") => OwnedEcxAdmissionContinuationV1::decode(bytes)
                .map(|input| Self::Admission(Box::new(input))),
            Some(b"ECXAI1") => OwnedEcxCancellationContinuationV1::decode(bytes)
                .map(|input| Self::Cancellation(Box::new(input))),
            Some(b"ECXCI2") => OwnedEcxNativeContinuationV1::decode(bytes)
                .map(|input| Self::Match(Box::new(input))),
            Some(b"ECXWI1") => OwnedEcxWithdrawalContinuationV1::decode(bytes)
                .map(|input| Self::Withdrawal(Box::new(input))),
            _ => Err(OwnedEcxNativeMatchV1::invalid()),
        }
    }

    pub fn continuation_program(&self) -> crate::Hash32 {
        match self {
            Self::Admission(input) => input.continuation_program,
            Self::Liquidation(input) => input.continuation_program,
            Self::Cancellation(input) => input.continuation_program,
            Self::Match(input) => input.continuation_program,
            Self::Withdrawal(input) => input.continuation_program,
        }
    }

    pub fn execute<P, S, V>(&self, parent: &P, simplicity: &S, verifier: &V)
        -> Result<Vec<u8>, EcxMatchExecutionErrorV1>
    where P: crate::FullAlphaReceiptVerifierV3,
        S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2,
        V: ConsensusProofVerifier,
    {
        match self {
            Self::Cancellation(input) => input.execute(parent, simplicity, verifier),
            Self::Admission(input) => input.execute(parent, simplicity, verifier),
            Self::Liquidation(input) => input.execute(parent, simplicity, verifier),
            Self::Match(input) => input.execute(parent, simplicity, verifier),
            Self::Withdrawal(input) => input.execute(parent, simplicity, verifier),
        }
    }
}

impl OwnedEcxNativeContinuationV1 {
    /// Verify the continuation role AND every public predecessor claim before
    /// opening its native result. All expected values come from the consumer.
    pub fn verify_receipt<V: ConsensusProofVerifier>(
        bytes: &[u8], proof: &[u8], verifier: &V,
        expected_program: crate::Hash32, predecessor_program: crate::Hash32,
        predecessor_binding: crate::Hash32, predecessor_checkpoint: crate::Hash32,
        native_binding: crate::Hash32, checkpoint: crate::Hash32,
        next: &EcxMatchCheckpointV2,
    ) -> Result<EcxNativeMatchPublicValuesV1, ProofErrorV2> {
        if bytes.len() != 546 || &bytes[..6] != b"ECXNC2"
            || !crate::alpha_sp1_program_id_is_canonical_v3(expected_program)
            || !crate::alpha_sp1_program_id_is_canonical_v3(predecessor_program)
            || predecessor_binding == [0;32] || predecessor_checkpoint == [0;32]
            || bytes[6..38] != predecessor_program
            || bytes[38..70] != predecessor_binding
            || bytes[70..102] != predecessor_checkpoint
            || bytes[102..134] != expected_program
        {
            return Err(ProofErrorV2::BindingMismatch("ECX continuation public claims"));
        }
        let result = EcxNativeMatchPublicValuesV1::decode(&bytes[134..])?;
        result.check_opening(native_binding, checkpoint, next)?;
        verifier.verify(expected_program, bytes, proof)
            .map_err(|_| ProofErrorV2::BindingMismatch("ECX continuation receipt verification"))?;
        Ok(result)
    }

    pub fn encode(&self) -> Result<Vec<u8>, EcxMatchExecutionErrorV1> {
        let payload = bincode::DefaultOptions::new().with_fixint_encoding()
            .with_limit((MAX_ECX_NATIVE_INPUT_BYTES - 6) as u64)
            .serialize(self).map_err(|_| OwnedEcxNativeMatchV1::invalid())?;
        let mut bytes = b"ECXCI2".to_vec(); bytes.extend(payload); Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, EcxMatchExecutionErrorV1> {
        if bytes.len() < 6 || bytes.len() > MAX_ECX_NATIVE_INPUT_BYTES || &bytes[..6] != b"ECXCI2" {
            return Err(OwnedEcxNativeMatchV1::invalid());
        }
        bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes()
            .with_limit((MAX_ECX_NATIVE_INPUT_BYTES - 6) as u64)
            .deserialize(&bytes[6..]).map_err(|_| OwnedEcxNativeMatchV1::invalid())
    }
    /// Preserves the initialization program/binding/checkpoint across recursion.
    /// ECXNC2 additionally exposes the recursive role, avoiding a private
    /// witness-selected self identity. Consumers must pin that role too.
    pub fn execute<P, S, V>(&self, parent: &P, simplicity: &S, verifier: &V)
        -> Result<Vec<u8>, EcxMatchExecutionErrorV1>
    where P: crate::FullAlphaReceiptVerifierV3,
        S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2,
        V: ConsensusProofVerifier,
    {
        self.verify_predecessor(verifier)?;
        let result = self.input.execute(parent, simplicity, verifier)?;
        let mut public = b"ECXNC2".to_vec();
        public.extend_from_slice(&self.predecessor_program);
        public.extend_from_slice(&self.predecessor_binding);
        public.extend_from_slice(&self.predecessor_checkpoint);
        public.extend_from_slice(&self.continuation_program);
        public.extend_from_slice(result.journal());
        Ok(public)
    }

    pub fn verify_predecessor<V: ConsensusProofVerifier>(&self, verifier: &V)
        -> Result<(), EcxMatchExecutionErrorV1> {
        self.verify_predecessor_opening(EcxContinuationOpening {
            binding: &self.input.binding, environment: &self.input.environment,
            parent: &self.input.execution.parent.binding, checkpoint: &self.input.checkpoint,
            checkpoint_pin: self.input.checkpoint_pin,
            native_checkpoint: &self.input.native_checkpoint, state_bytes: &self.input.state_bytes,
        }, verifier)
    }

}

impl OwnedEcxWithdrawalContinuationV1 {
    /// ECXWI1 carries an actual withdrawal plus its origin/recursive opening.
    /// Encoding alone does not execute or authenticate the withdrawal.
    pub fn encode(&self) -> Result<Vec<u8>, EcxMatchExecutionErrorV1> {
        let payload = bincode::DefaultOptions::new().with_fixint_encoding()
            .with_limit((MAX_ECX_NATIVE_INPUT_BYTES - 6) as u64)
            .serialize(self).map_err(|_| OwnedEcxNativeMatchV1::invalid())?;
        let mut bytes = b"ECXWI1".to_vec(); bytes.extend(payload); Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, EcxMatchExecutionErrorV1> {
        if bytes.len() < 6 || bytes.len() > MAX_ECX_NATIVE_INPUT_BYTES || &bytes[..6] != b"ECXWI1" {
            return Err(OwnedEcxNativeMatchV1::invalid());
        }
        bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes()
            .with_limit((MAX_ECX_NATIVE_INPUT_BYTES - 6) as u64)
            .deserialize(&bytes[6..]).map_err(|_| OwnedEcxNativeMatchV1::invalid())
    }

    /// Authenticate the predecessor before executing native inclusion and the
    /// complete-book withdrawal relation. Guest dispatch must explicitly select
    /// this operation; this host entrypoint does not establish a deployed role.
    pub fn execute<P, S, V>(&self, parent: &P, simplicity: &S, verifier: &V)
        -> Result<Vec<u8>, EcxMatchExecutionErrorV1>
    where P: crate::FullAlphaReceiptVerifierV3,
        S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2,
        V: ConsensusProofVerifier,
    {
        self.verify_predecessor(verifier)?;
        let result = self.input.execute(parent, simplicity, verifier)?;
        let mut public = b"ECXNC2".to_vec();
        public.extend_from_slice(&self.predecessor_program);
        public.extend_from_slice(&self.predecessor_binding);
        public.extend_from_slice(&self.predecessor_checkpoint);
        public.extend_from_slice(&self.continuation_program);
        public.extend_from_slice(result.journal());
        Ok(public)
    }

    /// Checks continuity only. The selected guest must additionally execute
    /// the withdrawal and enforce complete-book collateral reservation.
    pub fn verify_predecessor<V: ConsensusProofVerifier>(&self, verifier: &V)
        -> Result<(), EcxMatchExecutionErrorV1> {
        let withdrawal = &self.input;
        self.verify_predecessor_opening(EcxContinuationOpening {
            binding: &withdrawal.binding, environment: &withdrawal.environment,
            parent: &withdrawal.execution.parent.binding, checkpoint: &withdrawal.checkpoint,
            checkpoint_pin: withdrawal.checkpoint_pin,
            native_checkpoint: &withdrawal.native_checkpoint, state_bytes: &withdrawal.state_bytes,
        }, verifier)
    }
}

impl OwnedEcxCancellationContinuationV1 {
    pub fn encode(&self) -> Result<Vec<u8>, EcxMatchExecutionErrorV1> {
        let payload = bincode::DefaultOptions::new().with_fixint_encoding()
            .with_limit((MAX_ECX_NATIVE_INPUT_BYTES - 6) as u64)
            .serialize(self).map_err(|_| OwnedEcxNativeMatchV1::invalid())?;
        let mut bytes = b"ECXAI1".to_vec(); bytes.extend(payload); Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, EcxMatchExecutionErrorV1> {
        if bytes.len() > MAX_ECX_NATIVE_INPUT_BYTES || !bytes.starts_with(b"ECXAI1") {
            return Err(OwnedEcxNativeMatchV1::invalid());
        }
        bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes()
            .with_limit((MAX_ECX_NATIVE_INPUT_BYTES - 6) as u64)
            .deserialize(&bytes[6..]).map_err(|_| OwnedEcxNativeMatchV1::invalid())
    }
    pub fn execute<P, S, V>(&self, parent: &P, simplicity: &S, verifier: &V)
        -> Result<Vec<u8>, EcxMatchExecutionErrorV1>
    where P: crate::FullAlphaReceiptVerifierV3,
        S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2,
        V: ConsensusProofVerifier,
    {
        self.verify_predecessor_opening(EcxContinuationOpening {
            binding: &self.input.binding, environment: &self.input.environment,
            parent: &self.input.execution.parent.binding, checkpoint: &self.input.checkpoint,
            checkpoint_pin: self.input.checkpoint_pin,
            native_checkpoint: &self.input.native_checkpoint, state_bytes: &self.input.state_bytes,
        }, verifier)?;
        let result = self.input.execute(parent, simplicity)?;
        let mut public = b"ECXNC2".to_vec();
        public.extend_from_slice(&self.predecessor_program);
        public.extend_from_slice(&self.predecessor_binding);
        public.extend_from_slice(&self.predecessor_checkpoint);
        public.extend_from_slice(&self.continuation_program);
        public.extend_from_slice(result.journal());
        Ok(public)
    }
}

impl OwnedEcxAdmissionContinuationV1 {
    pub fn encode(&self) -> Result<Vec<u8>, EcxMatchExecutionErrorV1> {
        let payload = bincode::DefaultOptions::new().with_fixint_encoding()
            .with_limit((MAX_ECX_NATIVE_INPUT_BYTES - 6) as u64)
            .serialize(self).map_err(|_| OwnedEcxNativeMatchV1::invalid())?;
        let mut bytes = b"ECXOI1".to_vec(); bytes.extend(payload); Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, EcxMatchExecutionErrorV1> {
        if bytes.len() > MAX_ECX_NATIVE_INPUT_BYTES || !bytes.starts_with(b"ECXOI1") {
            return Err(OwnedEcxNativeMatchV1::invalid());
        }
        bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes()
            .with_limit((MAX_ECX_NATIVE_INPUT_BYTES - 6) as u64)
            .deserialize(&bytes[6..]).map_err(|_| OwnedEcxNativeMatchV1::invalid())
    }
    pub fn execute<P, S, V>(&self, parent: &P, simplicity: &S, verifier: &V)
        -> Result<Vec<u8>, EcxMatchExecutionErrorV1>
    where P: crate::FullAlphaReceiptVerifierV3,
        S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2,
        V: ConsensusProofVerifier,
    {
        self.verify_predecessor_opening(EcxContinuationOpening {
            binding: &self.input.binding, environment: &self.input.environment,
            parent: &self.input.execution.parent.binding, checkpoint: &self.input.checkpoint,
            checkpoint_pin: self.input.checkpoint_pin,
            native_checkpoint: &self.input.native_checkpoint, state_bytes: &self.input.state_bytes,
        }, verifier)?;
        let result = self.input.execute(parent, simplicity, verifier)?;
        let mut public = b"ECXNC2".to_vec();
        public.extend_from_slice(&self.predecessor_program);
        public.extend_from_slice(&self.predecessor_binding);
        public.extend_from_slice(&self.predecessor_checkpoint);
        public.extend_from_slice(&self.continuation_program);
        public.extend_from_slice(result.journal());
        Ok(public)
    }
}

pub type OwnedEcxLiquidationContinuationV1 = OwnedEcxContinuationEnvelopeV1<OwnedEcxNativeLiquidationV1>;

impl OwnedEcxLiquidationContinuationV1 {
    pub fn encode(&self) -> Result<Vec<u8>, EcxMatchExecutionErrorV1> {
        let payload = bincode::DefaultOptions::new().with_fixint_encoding()
            .with_limit((MAX_ECX_NATIVE_INPUT_BYTES - 6) as u64)
            .serialize(self).map_err(|_| OwnedEcxNativeMatchV1::invalid())?;
        let mut bytes = b"ECXLI1".to_vec(); bytes.extend(payload); Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, EcxMatchExecutionErrorV1> {
        if bytes.len() > MAX_ECX_NATIVE_INPUT_BYTES || !bytes.starts_with(b"ECXLI1") {
            return Err(OwnedEcxNativeMatchV1::invalid());
        }
        bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes()
            .with_limit((MAX_ECX_NATIVE_INPUT_BYTES - 6) as u64)
            .deserialize(&bytes[6..]).map_err(|_| OwnedEcxNativeMatchV1::invalid())
    }
    pub fn execute<P, S, V>(&self, parent: &P, simplicity: &S, verifier: &V)
        -> Result<Vec<u8>, EcxMatchExecutionErrorV1>
    where P: crate::FullAlphaReceiptVerifierV3,
        S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2,
        V: ConsensusProofVerifier,
    {
        self.verify_predecessor_opening(EcxContinuationOpening {
            binding: &self.input.binding, environment: &self.input.environment,
            parent: &self.input.execution.parent.binding, checkpoint: &self.input.checkpoint,
            checkpoint_pin: self.input.checkpoint_pin,
            native_checkpoint: &self.input.native_checkpoint, state_bytes: &self.input.state_bytes,
        }, verifier)?;
        let result = self.input.execute(parent, simplicity, verifier)?;
        let mut public = b"ECXNC2".to_vec();
        public.extend_from_slice(&self.predecessor_program);
        public.extend_from_slice(&self.predecessor_binding);
        public.extend_from_slice(&self.predecessor_checkpoint);
        public.extend_from_slice(&self.continuation_program);
        public.extend_from_slice(result.journal());
        Ok(public)
    }
}

impl<T> OwnedEcxContinuationEnvelopeV1<T> {
    fn verify_predecessor_opening<V: ConsensusProofVerifier>(
        &self, input: EcxContinuationOpening<'_>, verifier: &V,
    ) -> Result<(), EcxMatchExecutionErrorV1> {
        use EcxMatchExecutionErrorV1::Match;
        let origin = &self.initialization_binding;
        let current = input.binding;
        let origin_environment = crate::ecx_environment_v4::EcxExecutionEnvironmentV1::decode(
            &self.initialization_environment).map_err(|_| Self::invalid_environment())?;
        let environment = crate::ecx_environment_v4::EcxExecutionEnvironmentV1::decode(
            input.environment).map_err(|_| Self::invalid_environment())?;
        if origin_environment.commitment().ok() != Some(origin.environment)
            || origin_environment.bond_identity != environment.bond_identity
            || origin_environment.incremental_identity != environment.incremental_identity {
            return Err(Self::invalid_environment());
        }
        let parent = input.parent;
        let origin_parent = &self.initialization_parent;
        // Only the child checkpoint advances. Never let a recursive prover
        // replace the reviewed parent checkpoint, verifier roles or slot policy.
        if origin_parent.commitment().ok() != Some(origin.execution.parent_binding)
            || parent.parent != origin_parent.parent
            || parent.child_consensus_configuration_commitment != origin_parent.child_consensus_configuration_commitment
            || parent.child_genesis_hash_internal != origin_parent.child_genesis_hash_internal
            || parent.slot24_proposal_hash != origin_parent.slot24_proposal_hash
            || parent.slot24_activation_height != origin_parent.slot24_activation_height {
            return Err(Match(ProofErrorV2::BindingMismatch("ECX recursive parent policy")));
        }
        if origin.commitment().ok() != Some(self.predecessor_binding)
            || origin.execution.execution_policy != current.execution.execution_policy
            || origin.execution.simplicity_evaluator_program_id != current.execution.simplicity_evaluator_program_id
            || origin.execution.deposit_configuration != current.execution.deposit_configuration
            || origin.evaluator_source_closure != current.evaluator_source_closure
            || origin.genesis_bindings != current.genesis_bindings
            || origin.successor != current.successor {
            return Err(Match(ProofErrorV2::BindingMismatch("ECX recursive execution policy")));
        }
        if !crate::alpha_sp1_program_id_is_canonical_v3(self.continuation_program)
            || self.continuation_program == self.predecessor_program {
            return Err(Match(ProofErrorV2::BindingMismatch("ECX recursive role")));
        }
        if !self.recursive {
            return verify_native_predecessor_opening(&self.predecessor_journal,
                &self.predecessor_proof, verifier, self.predecessor_program,
                self.predecessor_binding, self.predecessor_checkpoint,
                input.checkpoint, input.checkpoint_pin, input.native_checkpoint, input.state_bytes);
        }
        if self.predecessor_journal.len() != 546 {
            return Err(OwnedEcxNativeMatchV1::invalid());
        }
        let opening = EcxNativeMatchPublicValuesV1::decode(&self.predecessor_journal[134..]).map_err(Match)?;
        let previous = OwnedEcxNativeContinuationV1::verify_receipt(&self.predecessor_journal, &self.predecessor_proof,
            verifier, self.continuation_program, self.predecessor_program,
            self.predecessor_binding, self.predecessor_checkpoint,
            opening.native_binding, opening.predecessor_checkpoint, input.checkpoint).map_err(Match)?;
        if previous.successor_checkpoint != input.checkpoint_pin
            || previous.state.encode().map_err(Match)?.as_slice() != input.state_bytes
            || input.checkpoint.native_projection(input.checkpoint_pin).ok().as_ref()
                != Some(input.native_checkpoint) {
            return Err(Match(ProofErrorV2::BindingMismatch("ECX recursive opening")));
        }
        Ok(())
    }

    fn invalid_environment() -> EcxMatchExecutionErrorV1 {
        EcxMatchExecutionErrorV1::Match(ProofErrorV2::BindingMismatch("ECX recursive environment identity"))
    }
}

/// Shared opening checks for both operation transports. Expected receipt
/// identities must be supplied by the consuming guest, not inferred here.
#[allow(clippy::too_many_arguments)]
fn verify_native_predecessor_opening<V: ConsensusProofVerifier>(
    journal: &[u8], proof: &[u8], verifier: &V,
    expected_program: crate::Hash32, expected_binding: crate::Hash32,
    expected_predecessor: crate::Hash32, checkpoint: &EcxMatchCheckpointV2,
    checkpoint_pin: crate::Hash32,
    native_checkpoint: &crate::child_execution_state_v4::ChildExecutionCheckpointV5,
    state_bytes: &[u8],
) -> Result<(), EcxMatchExecutionErrorV1> {
    use EcxMatchExecutionErrorV1::Match;
    let previous = EcxNativeMatchPublicValuesV1::verify_receipt(
        journal, proof, verifier, expected_program, expected_binding,
        expected_predecessor, checkpoint).map_err(Match)?;
    if previous.successor_checkpoint != checkpoint_pin
        || previous.state.encode().map_err(Match)?.as_slice() != state_bytes
        || checkpoint.native_projection(checkpoint_pin).ok().as_ref() != Some(native_checkpoint)
    {
        return Err(Match(ProofErrorV2::BindingMismatch("ECX predecessor receipt opening")));
    }
    Ok(())
}

impl OwnedEcxNativeMatchV1 {
    /// Authenticate continuation from a prior native receipt. Expected program,
    /// binding and predecessor are caller-selected trust roots, not witness hashes.
    /// This checks the opening only; `execute` must still validate the next block.
    pub fn verify_predecessor_receipt<V: ConsensusProofVerifier>(
        &self, journal: &[u8], proof: &[u8], verifier: &V,
        expected_program: crate::Hash32, expected_binding: crate::Hash32,
        expected_predecessor: crate::Hash32,
    ) -> Result<(), EcxMatchExecutionErrorV1> {
        verify_native_predecessor_opening(journal, proof, verifier, expected_program,
            expected_binding, expected_predecessor, &self.checkpoint,
            self.checkpoint_pin, &self.native_checkpoint, &self.state_bytes)
    }

    pub fn execute_after_receipt<P, S, V>(
        &self, journal: &[u8], proof: &[u8], expected_program: crate::Hash32,
        expected_binding: crate::Hash32, expected_predecessor: crate::Hash32,
        parent: &P, simplicity: &S, verifier: &V,
    ) -> Result<ExecutedEcxNativeMatchV1, EcxMatchExecutionErrorV1>
    where P: crate::FullAlphaReceiptVerifierV3,
        S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2,
        V: ConsensusProofVerifier,
    {
        self.verify_predecessor_receipt(journal, proof, verifier, expected_program,
            expected_binding, expected_predecessor)?;
        self.execute(parent, simplicity, verifier)
    }

    pub fn encode(&self) -> Result<Vec<u8>, EcxMatchExecutionErrorV1> {
        let payload = bincode::DefaultOptions::new().with_fixint_encoding()
            .with_limit((MAX_ECX_NATIVE_INPUT_BYTES - 6) as u64)
            .serialize(self).map_err(|_| Self::invalid())?;
        let mut bytes = b"ECXNI1".to_vec(); bytes.extend(payload); Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, EcxMatchExecutionErrorV1> {
        if bytes.len() < 6 || bytes.len() > MAX_ECX_NATIVE_INPUT_BYTES || &bytes[..6] != b"ECXNI1" {
            return Err(Self::invalid());
        }
        bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes()
            .with_limit((MAX_ECX_NATIVE_INPUT_BYTES - 6) as u64)
            .deserialize(&bytes[6..]).map_err(|_| Self::invalid())
    }
    fn invalid() -> EcxMatchExecutionErrorV1 {
        EcxMatchExecutionErrorV1::Native(AlphaChildExecutionErrorV3::Input)
    }
    pub fn execute<P, S, V>(&self, parent: &P, simplicity: &S, verifier: &V)
        -> Result<ExecutedEcxNativeMatchV1, EcxMatchExecutionErrorV1>
    where P: crate::FullAlphaReceiptVerifierV3,
        S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2,
        V: ecx_proof_core::ecx_match_input_v1::ConsensusProofVerifier,
    {
        use EcxMatchExecutionErrorV1::Match;
        use crate::ecx_deposit_membership_v1::EcxCoinMembershipV1;
        let prior = EcxSuccessorStateV1::decode(&self.state_bytes).map_err(Match)?;
        let environment = crate::ecx_environment_v4::EcxExecutionEnvironmentV1::decode(&self.environment)
            .map_err(|_| Self::invalid())?;
        let source = elements::encode::deserialize(&self.source_transaction).map_err(|_| Self::invalid())?;
        let successor = elements::encode::deserialize(&self.successor_transaction).map_err(|_| Self::invalid())?;
        let cash = |ledger: &[(ecx_protocol_core::TraderLeafV2, Vec<u8>)]| ledger.iter()
            .map(|(_, bytes)| ecx_protocol_core::ecx_cash_account_v1::EcxCashAccountV1::from_bytes(bytes))
            .collect::<Result<Vec<_>, _>>();
        let prior_cash = cash(&self.prior_accounts).map_err(|_| Self::invalid())?;
        let successor_cash = cash(&self.successor_accounts).map_err(|_| Self::invalid())?;
        let prior_accounts: Vec<_> = self.prior_accounts.iter().zip(&prior_cash)
            .map(|((position, _), cash)| (position, cash)).collect();
        let successor_accounts: Vec<_> = self.successor_accounts.iter().zip(&successor_cash)
            .map(|((position, _), cash)| (position, cash)).collect();
        execute_alpha_ecx_match_v1(&self.execution, &self.binding, &self.native_checkpoint,
            &self.deposit_policy, &environment, self.native_binding_pin, self.checkpoint_pin,
            EcxMatchExecutionWitnessV1 {
                transaction_index: self.transaction_index as usize, checkpoint: &self.checkpoint,
                prior: &prior, bindings: self.bindings, economics: self.economics,
                journal: &self.journal, proof: &self.proof,
                vault: EcxTradingVaultWitnessV1 {
                    source_outpoint: self.checkpoint.state.vault_outpoint,
                    source_transaction: &source, successor_transaction: &successor,
                    successor_vout: self.successor_vout,
                    source_script_sha256: prior.vault_script_sha256,
                    successor_script_sha256: self.successor_script_sha256,
                    prior_accounts: &prior_accounts, successor_accounts: &successor_accounts,
                }, membership: EcxCoinMembershipV1 { leaf: &self.coin, path: &self.path },
                successor_membership: EcxCoinMembershipV1 { leaf: &self.successor_coin, path: &self.successor_path },
            }, parent, simplicity, verifier)
    }
}

pub struct EcxMatchExecutionWitnessV1<'a> {
    pub transaction_index: usize,
    pub checkpoint: &'a EcxMatchCheckpointV2,
    pub prior: &'a EcxSuccessorStateV1,
    pub bindings: ecx_protocol_core::ecx_configuration_v1::EcxSuccessorBindingsV1,
    pub economics: ecx_protocol_core::ecx_configuration_v1::EcxConfigurationV1,
    pub journal: &'a [u8],
    pub proof: &'a [u8],
    pub vault: EcxTradingVaultWitnessV1<'a>,
    pub membership: crate::ecx_deposit_membership_v1::EcxCoinMembershipV1<'a>,
    pub successor_membership: crate::ecx_deposit_membership_v1::EcxCoinMembershipV1<'a>,
}

/// Native withdrawal outer relation. Its journal has the same state/checkpoint
/// opening as matches; consumers must still pin the selected guest identity.
/// This function alone does not authenticate recursive predecessor receipts.
/// An enclosing acceptance guest must also enforce outstanding-order position
/// reservations; fee reservation and current-position margin are not that policy.
#[allow(clippy::too_many_arguments)]
pub fn execute_alpha_ecx_withdrawal_v1<P, S, V>(
    input: &AlphaChildExecutionInputV3,
    binding: &crate::child_execution_statement_v4::AlphaChildExecutionBindingV5,
    checkpoint: &crate::child_execution_state_v4::ChildExecutionCheckpointV5,
    deposit_policy: &crate::native_deposit_policy_v4::AlphaDepositPolicyV4,
    environment: &crate::ecx_environment_v4::EcxExecutionEnvironmentV1,
    expected_native_binding: crate::Hash32, expected_ecx_checkpoint: crate::Hash32,
    continuity: &EcxMatchCheckpointV2, prior: &EcxSuccessorStateV1,
    transaction_index: usize,
    withdrawal: &ecx_proof_core::ecx_withdrawal_input_v1::EcxWithdrawalInputV1,
    membership: crate::ecx_deposit_membership_v1::EcxCoinMembershipV1<'_>,
    successor_membership: crate::ecx_deposit_membership_v1::EcxCoinMembershipV1<'_>,
    parent: &P, simplicity: &S, verifier: &V,
) -> Result<ExecutedEcxNativeMatchV1, EcxMatchExecutionErrorV1>
where P: crate::FullAlphaReceiptVerifierV3,
    S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2,
    V: ConsensusProofVerifier,
{
    use EcxMatchExecutionErrorV1::{Native, Match};
    let invalid = || Native(AlphaChildExecutionErrorV3::Binding);
    if expected_native_binding == [0;32]
        || binding.commitment().map_err(Native)? != expected_native_binding
        || continuity.native_projection(expected_ecx_checkpoint).map_err(|_| invalid())? != *checkpoint
    { return Err(invalid()); }
    let (checked, context) = crate::child_execution_guest_v4::execute_alpha_child_native_v5(
        input, binding, checkpoint, deposit_policy, environment, parent, simplicity).map_err(Native)?;
    let inner_pin = continuity.state.commitment().map_err(|_| invalid())?;
    let (state, _, next) = context.advance_ecx_owned_withdrawal(&checked, transaction_index,
        &continuity.state, inner_pin, prior, withdrawal, membership, successor_membership,
        verifier).map_err(Match)?;
    let (statement, endpoint) = crate::conversion_parent_link_v3::authenticate_alpha_bmm_endpoint_v4(
        &input.parent, binding.execution.parent_binding, parent).map_err(|_| invalid())?;
    if &statement != checked.parent() { return Err(invalid()); }
    let next = EcxMatchCheckpointV2 { state: next, bmm_endpoint: Some(endpoint.to_vec()) };
    let public_values = EcxNativeMatchPublicValuesV1 {
        native_binding: expected_native_binding, predecessor_checkpoint: expected_ecx_checkpoint,
        successor_checkpoint: next.commitment().map_err(|_| invalid())?, state,
    };
    public_values.check_opening(expected_native_binding, expected_ecx_checkpoint, &next).map_err(Match)?;
    let journal = public_values.canonical_bytes().map_err(Match)?;
    Ok(ExecutedEcxNativeMatchV1 { public_values, checkpoint: next, journal })
}

#[derive(Debug)]
pub enum EcxMatchExecutionErrorV1 {
    Native(AlphaChildExecutionErrorV3),
    Match(ProofErrorV2),
}

pub const ECX_NATIVE_MATCH_PUBLIC_BYTES_V1: usize = 412;

/// Native inclusion journal, distinct from the ECXMJ1 match child. Decoding
/// is not proof verification: consumers must verify the selected guest and
/// independently pin both the native binding and predecessor checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcxNativeMatchPublicValuesV1 {
    pub native_binding: crate::Hash32,
    pub predecessor_checkpoint: crate::Hash32,
    pub successor_checkpoint: crate::Hash32,
    pub state: EcxSuccessorStateV1,
}

impl EcxNativeMatchPublicValuesV1 {
    /// The program ID is the independently selected native-outer role, never
    /// the match-child ID supplied by the witness. No default identity exists.
    pub fn verify_receipt<V: ecx_proof_core::ecx_match_input_v1::ConsensusProofVerifier>(
        bytes: &[u8], proof: &[u8], verifier: &V, expected_program: crate::Hash32,
        native_binding: crate::Hash32, predecessor: crate::Hash32, next: &EcxMatchCheckpointV2,
    ) -> Result<Self, ProofErrorV2> {
        if !crate::alpha_sp1_program_id_is_canonical_v3(expected_program) {
            return Err(ProofErrorV2::BindingMismatch("ECX native program identity"));
        }
        let value = Self::decode(bytes)?;
        value.check_opening(native_binding, predecessor, next)?;
        verifier.verify(expected_program, bytes, proof)
            .map_err(|_| ProofErrorV2::BindingMismatch("ECX native receipt verification"))?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> Result<[u8; ECX_NATIVE_MATCH_PUBLIC_BYTES_V1], ProofErrorV2> {
        if [self.native_binding, self.predecessor_checkpoint, self.successor_checkpoint].contains(&[0;32]) {
            return Err(ProofErrorV2::BindingMismatch("ECX native journal identity"));
        }
        let mut bytes = [0; ECX_NATIVE_MATCH_PUBLIC_BYTES_V1];
        bytes[..6].copy_from_slice(b"ECXNJ1");
        bytes[6..38].copy_from_slice(&self.native_binding);
        bytes[38..70].copy_from_slice(&self.predecessor_checkpoint);
        bytes[70..102].copy_from_slice(&self.successor_checkpoint);
        bytes[102..].copy_from_slice(&self.state.encode()?);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProofErrorV2> {
        if bytes.len() != ECX_NATIVE_MATCH_PUBLIC_BYTES_V1 || &bytes[..6] != b"ECXNJ1" {
            return Err(ProofErrorV2::BindingMismatch("ECX native journal encoding"));
        }
        let value = Self {
            native_binding: bytes[6..38].try_into().unwrap(),
            predecessor_checkpoint: bytes[38..70].try_into().unwrap(),
            successor_checkpoint: bytes[70..102].try_into().unwrap(),
            state: EcxSuccessorStateV1::decode(&bytes[102..])?,
        };
        value.canonical_bytes()?;
        Ok(value)
    }

    /// Open a receipt-authenticated successor for the next step. This checks
    /// transport linkage, not receipt validity or later-chain finality.
    pub fn check_opening(&self, native_binding: crate::Hash32, predecessor: crate::Hash32,
        next: &EcxMatchCheckpointV2) -> Result<(), ProofErrorV2> {
        self.canonical_bytes()?;
        if self.native_binding != native_binding || self.predecessor_checkpoint != predecessor
            || next.commitment().ok() != Some(self.successor_checkpoint)
            || next.state.exchange_state_root != self.state.digest()?
            || next.state.bindings_hash != self.state.bindings_hash
            || u64::from(next.state.execution.height) != self.state.sidechain_height {
            return Err(ProofErrorV2::BindingMismatch("ECX native journal opening"));
        }
        Ok(())
    }
}

/// Only successful native execution can construct this result. A guest commits
/// `journal()`; the host retains `checkpoint()` as the next-step preimage.
pub struct ExecutedEcxNativeMatchV1 {
    public_values: EcxNativeMatchPublicValuesV1,
    checkpoint: EcxMatchCheckpointV2,
    journal: [u8; ECX_NATIVE_MATCH_PUBLIC_BYTES_V1],
}
impl ExecutedEcxNativeMatchV1 {
    pub fn public_values(&self) -> &EcxNativeMatchPublicValuesV1 { &self.public_values }
    pub fn checkpoint(&self) -> &EcxMatchCheckpointV2 { &self.checkpoint }
    pub fn journal(&self) -> &[u8; ECX_NATIVE_MATCH_PUBLIC_BYTES_V1] { &self.journal }
}

/// Execute the native block first, then validate its final ECX match and vault.
/// Independent expected commitments are mandatory; hashing this witness is not
/// an acceptable source of either pin. This function deliberately does not emit
/// a V5 capital checkpoint or claim legacy USDD projection compatibility.
#[allow(clippy::too_many_arguments)]
pub fn execute_alpha_ecx_match_v1<P, S, V>(
    input: &AlphaChildExecutionInputV3,
    binding: &crate::child_execution_statement_v4::AlphaChildExecutionBindingV5,
    checkpoint: &crate::child_execution_state_v4::ChildExecutionCheckpointV5,
    deposit_policy: &crate::native_deposit_policy_v4::AlphaDepositPolicyV4,
    environment: &crate::ecx_environment_v4::EcxExecutionEnvironmentV1,
    expected_native_binding: crate::Hash32,
    expected_ecx_checkpoint: crate::Hash32,
    witness: EcxMatchExecutionWitnessV1<'_>,
    parent: &P, simplicity: &S, match_verifier: &V,
) -> Result<ExecutedEcxNativeMatchV1, EcxMatchExecutionErrorV1>
where
    P: crate::FullAlphaReceiptVerifierV3,
    S: ecx_full_consensus_validator_v2::elements_v2::ElementsSimplicityReceiptVerifierV2,
    V: ecx_proof_core::ecx_match_input_v1::ConsensusProofVerifier,
{
    use EcxMatchExecutionErrorV1::{Native, Match};
    if expected_native_binding == [0;32]
        || binding.commitment().map_err(Native)? != expected_native_binding
    { return Err(Native(AlphaChildExecutionErrorV3::Binding)); }
    // Reject invalid continuity before paying the cost of native execution.
    let projected = witness.checkpoint.native_projection(expected_ecx_checkpoint)
        .map_err(|_| Native(AlphaChildExecutionErrorV3::Binding))?;
    if &projected != checkpoint
    { return Err(Native(AlphaChildExecutionErrorV3::Binding)); }
    let (checked, context) = crate::child_execution_guest_v4::execute_alpha_child_native_v5(
        input, binding, checkpoint, deposit_policy, environment, parent, simplicity)
        .map_err(Native)?;
    // The V1 preimage is authenticated transitively by the checked V2 pin.
    let inner_pin = witness.checkpoint.state.commitment()
        .map_err(|_| Native(AlphaChildExecutionErrorV3::Binding))?;
    let (state, next) = context.advance_ecx_match_checkpoint(&checked, witness.transaction_index,
        &witness.checkpoint.state, inner_pin, witness.prior,
        witness.bindings, witness.economics, witness.journal, witness.proof,
        match_verifier, &witness.vault, witness.membership, witness.successor_membership)
        .map_err(Match)?;
    let (statement, endpoint) = crate::conversion_parent_link_v3::authenticate_alpha_bmm_endpoint_v4(
        &input.parent, binding.execution.parent_binding, parent)
        .map_err(|_| Native(AlphaChildExecutionErrorV3::Binding))?;
    if &statement != checked.parent() {
        return Err(Native(AlphaChildExecutionErrorV3::Binding));
    }
    let next = EcxMatchCheckpointV2 { state: next, bmm_endpoint: Some(endpoint.to_vec()) };
    let public_values = EcxNativeMatchPublicValuesV1 {
        native_binding: expected_native_binding, predecessor_checkpoint: expected_ecx_checkpoint,
        successor_checkpoint: next.commitment().map_err(|_| Native(AlphaChildExecutionErrorV3::Binding))?,
        state,
    };
    public_values.check_opening(expected_native_binding, expected_ecx_checkpoint, &next).map_err(Match)?;
    let journal = public_values.canonical_bytes().map_err(Match)?;
    Ok(ExecutedEcxNativeMatchV1 { public_values, checkpoint: next, journal })
}
