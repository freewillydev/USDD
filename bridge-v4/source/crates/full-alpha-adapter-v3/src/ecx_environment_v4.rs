//! Versioned wire representation of the node's ECX execution environment.
//!
//! This is not C ABI memory and is not an authentication mechanism. The child
//! relation must derive these values from authenticated chain/configuration
//! state. Native verifier callbacks must come from the linked implementation,
//! never from this wire input. The recovered legacy backend cannot consume it.
use crate::{tagged_hash, Hash32};

const MAGIC: &[u8; 8] = b"ECXENV1\0";
pub const ENCODED_LENGTH: usize = 543;

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct EcxExecutionEnvironmentV1 {
    pub prior_active_root: Option<Hash32>,
    pub forced_inbox_root: Option<Hash32>,
    pub deposit_inbox_root: Option<Hash32>,
    pub forced_processed_cursor: u64,
    pub deposit_processed_cursor: u64,
    pub current_bmm_parent: Option<Parent>,
    pub bond_identity: Option<BondIdentity>,
    pub incremental_identity: Option<IncrementalIdentity>,
    pub projection: Option<Projection>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parent {
    pub block_hash_wire: Hash32,
    pub height: u64,
    pub median_time_past: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BondIdentity {
    pub configuration_hash: Hash32,
    pub asset_id: Hash32,
    pub deployment_commitment: Hash32,
    pub transition_cmr: Hash32,
    pub collateral_vault_script_sha256: Hash32,
    pub collateral_vault_cmr: Hash32,
    pub insurance_reserve_script_sha256: Hash32,
    pub insurance_reserve_cmr: Hash32,
}

impl BondIdentity {
    fn hashes(&self) -> [Hash32; 8] {
        [self.configuration_hash, self.asset_id, self.deployment_commitment,
         self.transition_cmr, self.collateral_vault_script_sha256,
         self.collateral_vault_cmr, self.insurance_reserve_script_sha256,
         self.insurance_reserve_cmr]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncrementalIdentity {
    pub activation_cmr: Hash32,
    pub successor_transition_cmr: Hash32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Projection {
    pub prior_active_bond_inbox_root: Hash32,
    pub prior_active_bond_inbox_count: u64,
    pub current_sidechain_height: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error { NonCanonical, InvalidEnvironment }

/// Context authenticated for one checkpoint and Alpha P->Q edge. Construction
/// never accepts a host's precomputed receipt context. Frozen evaluator and
/// environment commitments must come from the enclosing reviewed configuration,
/// not from the supplied environment. This does not prove child execution.
pub struct CheckedAlphaExecutionContextV4 {
    context: ecx_full_consensus_validator_v2::alpha_simplicity_receipt_v3::AlphaExecutionContextV3,
    checkpoint: crate::child_execution_state_v4::ChildExecutionCheckpointV4,
    environment: EcxExecutionEnvironmentV1,
    parent_binding: Hash32,
}

impl CheckedAlphaExecutionContextV4 {
    /// Permissionless liquidation of the pinned predecessor in a checked
    /// native block. The enclosing receipt authenticates the checkpoint pin;
    /// this method derives the clock, checks both coins and binds the final
    /// exchange header to the oracle-authorized economic transition.
    #[allow(clippy::too_many_arguments)]
    pub fn advance_ecx_liquidation_checkpoint<V: ecx_proof_core::ecx_match_input_v1::ConsensusProofVerifier>(
        &self,
        executed: &crate::native_child_block_v3::ParentBoundCheckedChildState,
        transaction_index: usize,
        checkpoint: &crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV1,
        frozen_checkpoint: Hash32,
        prior: &ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1,
        bindings: ecx_protocol_core::ecx_configuration_v1::EcxSuccessorBindingsV1,
        economics: ecx_protocol_core::ecx_configuration_v1::EcxConfigurationV1,
        configuration: &ecx_protocol_core::FrozenConfigurationV2,
        truthcoin: &ecx_proof_core::ecx_match_input_v1::TruthcoinConsensusProofV1,
        ecx_btc: &ecx_proof_core::ConversionLegConsensusProofV2,
        usdd_usd: &ecx_proof_core::ConversionLegConsensusProofV2,
        verifier: &V,
        funding: &ecx_protocol_core::funding_v2::FundingStateV2,
        target: ecx_protocol_core::ecx_cash_account_v1::EcxAccountOpeningV1<'_>,
        makers: &[ecx_protocol_core::ecx_cash_account_v1::EcxAccountOpeningV1<'_>],
        clearing: ecx_protocol_core::ecx_cash_account_v1::EcxAccountOpeningV1<'_>,
        insurance: ecx_protocol_core::ecx_cash_account_v1::EcxAccountOpeningV1<'_>,
        orders: &[(&ecx_protocol_core::ecx_order_v1::EcxAdmittedOrderV2, &[Hash32])],
        source_orders: &[&ecx_protocol_core::ecx_order_v1::EcxAdmittedOrderV2],
        fills: &[(Hash32, u64)],
        vault: &ecx_proof_core::ecx_execution_v1::EcxTradingVaultWitnessV1<'_>,
        membership: crate::ecx_deposit_membership_v1::EcxCoinMembershipV1<'_>,
        successor_membership: crate::ecx_deposit_membership_v1::EcxCoinMembershipV1<'_>,
    ) -> Result<(ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1,
        ecx_protocol_core::funding_v2::FundingStateV2,
        crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV1), ecx_proof_core::proof_v2::ProofErrorV2> {
        let invalid = || ecx_proof_core::proof_v2::ProofErrorV2::BindingMismatch(
            "ECX liquidation checkpoint");
        checkpoint.require_frozen(frozen_checkpoint).map_err(|_| invalid())?;
        if checkpoint.execution != self.checkpoint.execution
            || checkpoint.exchange_state_root != prior.digest()?
            || checkpoint.bindings_hash != bindings.digest()?
        { return Err(invalid()); }
        self.check_match_execution_binding(executed.ecx_context(), executed.ecx_checkpoint)
            .map_err(|_| invalid())?;
        let prepared = self.prepare_ecx_match_state(prior, bindings).map_err(|_| invalid())?;
        let child = executed.child();
        if child.next_checkpoint().is_none()
            || child.foundation().block.txdata.get(transaction_index) != Some(vault.successor_transaction)
        { return Err(invalid()); }
        crate::ecx_deposit_membership_v1::check_coin(
            child.transaction_pre_utxo_root(transaction_index).ok_or_else(invalid)?,
            membership, checkpoint.vault_outpoint, vault.source_transaction)?;
        let (state, funding, _) = ecx_proof_core::ecx_execution_v1::verify_ecx_oracle_liquidation_batch_v1(
            prepared.digest()?, &prepared, checkpoint.vault_outpoint, bindings,
            economics, configuration, truthcoin, ecx_btc, usdd_usd, verifier,
            funding, target, makers, clearing, insurance, orders, source_orders, fills, vault)?;
        let header = &child.foundation().native_header;
        if header.base.version & crate::native_header_v3::EXCHANGE == 0
            || header.exchange != state.digest()? { return Err(invalid()); }
        let outpoint = elements::OutPoint {
            txid: vault.successor_transaction.txid(), vout: vault.successor_vout };
        crate::ecx_deposit_membership_v1::check_coin(child.roots().utxo_root,
            successor_membership, outpoint, vault.successor_transaction)?;
        let next = crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV1 {
            execution: child.next_checkpoint().ok_or_else(invalid)?.clone(),
            exchange_state_root: state.digest()?, bindings_hash: checkpoint.bindings_hash,
            vault_outpoint: outpoint,
        };
        next.commitment().map_err(|_| invalid())?;
        Ok((state, funding, next))
    }

    /// Owned transport reuses the native liquidation relation and vault decoder.
    #[allow(clippy::too_many_arguments)]
    pub fn advance_ecx_owned_liquidation<V: ecx_proof_core::ecx_match_input_v1::ConsensusProofVerifier>(
        &self, executed: &crate::native_child_block_v3::ParentBoundCheckedChildState,
        transaction_index: usize,
        checkpoint: &crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV1,
        frozen_checkpoint: Hash32,
        prior: &ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1,
        input: &ecx_proof_core::ecx_liquidation_input_v1::EcxLiquidationInputV1,
        membership: crate::ecx_deposit_membership_v1::EcxCoinMembershipV1<'_>,
        successor_membership: crate::ecx_deposit_membership_v1::EcxCoinMembershipV1<'_>,
        verifier: &V,
    ) -> Result<(ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1,
        ecx_protocol_core::funding_v2::FundingStateV2,
        crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV1), ecx_proof_core::proof_v2::ProofErrorV2> {
        let invalid = || ecx_proof_core::proof_v2::ProofErrorV2::BindingMismatch("ECX owned liquidation opening");
        let prepared = self.prepare_ecx_match_state(prior, input.bindings).map_err(|_| invalid())?;
        if input.expected_state != prepared.digest()? || input.state_bytes != prepared.encode()? {
            return Err(invalid());
        }
        input.with_decoded_witness(|_, outpoint, target, makers, clearing, insurance,
            orders, source_orders, vault| {
            if outpoint != checkpoint.vault_outpoint { return Err(invalid()); }
            self.advance_ecx_liquidation_checkpoint(executed, transaction_index, checkpoint,
                frozen_checkpoint, prior, input.bindings, input.economics, &input.configuration,
                &input.truthcoin, &input.ecx_btc, &input.usdd_usd, verifier, &input.funding,
                target, makers, clearing, insurance, orders, source_orders, &input.fills,
                vault, membership, successor_membership)
        })
    }

    /// Admit only in the checked block, consuming the pinned predecessor vault.
    /// The outer continuation must authenticate the checkpoint and role pins.
    #[allow(clippy::too_many_arguments)]
    pub fn advance_ecx_owned_admission<V: ecx_proof_core::ecx_match_input_v1::ConsensusProofVerifier>(
        &self,
        executed: &crate::native_child_block_v3::ParentBoundCheckedChildState,
        transaction_index: usize,
        checkpoint: &crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV1,
        frozen_checkpoint: Hash32,
        prior: &ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1,
        input: &ecx_proof_core::ecx_admission_input_v1::EcxAdmissionInputV1,
        membership: crate::ecx_deposit_membership_v1::EcxCoinMembershipV1<'_>,
        successor_membership: crate::ecx_deposit_membership_v1::EcxCoinMembershipV1<'_>,
        verifier: &V,
    ) -> Result<(ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1,
        ecx_protocol_core::funding_v2::FundingStateV2,
        crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV1), ecx_proof_core::proof_v2::ProofErrorV2> {
        let invalid = || ecx_proof_core::proof_v2::ProofErrorV2::BindingMismatch("ECX native admission");
        checkpoint.require_frozen(frozen_checkpoint).map_err(|_| invalid())?;
        if checkpoint.execution != self.checkpoint.execution
            || checkpoint.exchange_state_root != prior.digest()?
            || checkpoint.bindings_hash != input.bindings.digest()?
        { return Err(invalid()); }
        self.check_match_execution_binding(executed.ecx_context(), executed.ecx_checkpoint)
            .map_err(|_| invalid())?;
        let prepared = self.prepare_ecx_match_state(prior, input.bindings).map_err(|_| invalid())?;
        if input.expected_state != prepared.digest()? || input.state_bytes != prepared.encode()? {
            return Err(invalid());
        }
        let child = executed.child();
        let (state, funding) = input.with_decoded_witness(|_, outpoint, account, vault, orders| {
            if outpoint != checkpoint.vault_outpoint
                || child.next_checkpoint().is_none()
                || child.foundation().block.txdata.get(transaction_index) != Some(vault.successor_transaction)
            { return Err(invalid()); }
            crate::ecx_deposit_membership_v1::check_coin(
                child.transaction_pre_utxo_root(transaction_index).ok_or_else(invalid)?,
                membership, outpoint, vault.source_transaction)?;
            let result = ecx_proof_core::ecx_execution_v1::verify_ecx_oracle_admission_v1(
                input.expected_state, &prepared, outpoint, input.bindings, input.economics,
                &input.configuration, &input.truthcoin, &input.ecx_btc, &input.usdd_usd,
                verifier, &input.funding, &input.matcher, &input.receipt, input.signed.clone(),
                account, &input.absence_siblings, orders, vault)?;
            let header = &child.foundation().native_header;
            if header.base.version & crate::native_header_v3::EXCHANGE == 0
                || header.exchange != result.0.digest()? { return Err(invalid()); }
            crate::ecx_deposit_membership_v1::check_coin(child.roots().utxo_root,
                successor_membership, elements::OutPoint {
                    txid: vault.successor_transaction.txid(), vout: vault.successor_vout },
                vault.successor_transaction)?;
            Ok(result)
        })?;
        let next = crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV1 {
            execution: child.next_checkpoint().ok_or_else(invalid)?.clone(),
            exchange_state_root: state.digest()?, bindings_hash: checkpoint.bindings_hash,
            vault_outpoint: successor_membership.leaf.outpoint,
        };
        next.commitment().map_err(|_| invalid())?;
        Ok((state, funding, next))
    }

    /// Bind the owned relation's opening to the authenticated native clock.
    /// Reuse the checkpoint transition and the sole owned ledger decoder.
    #[allow(clippy::too_many_arguments)]
    pub fn advance_ecx_owned_cancellation(
        &self,
        executed: &crate::native_child_block_v3::ParentBoundCheckedChildState,
        transaction_index: usize,
        checkpoint: &crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV1,
        frozen_checkpoint: Hash32,
        prior: &ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1,
        input: &ecx_proof_core::ecx_cancellation_input_v1::EcxCancellationInputV1,
        membership: crate::ecx_deposit_membership_v1::EcxCoinMembershipV1<'_>,
        successor_membership: crate::ecx_deposit_membership_v1::EcxCoinMembershipV1<'_>,
    ) -> Result<(ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1,
        crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV1), ecx_proof_core::proof_v2::ProofErrorV2> {
        let invalid = || ecx_proof_core::proof_v2::ProofErrorV2::BindingMismatch(
            "ECX owned cancellation opening");
        let prepared = self.prepare_ecx_match_state(prior, input.bindings)
            .map_err(|_| invalid())?;
        if input.expected_state != prepared.digest()? || input.state_bytes != prepared.encode()? {
            return Err(invalid());
        }
        input.with_decoded_witness(|_, outpoint, account, vault| {
            if outpoint != checkpoint.vault_outpoint { return Err(invalid()); }
            self.advance_ecx_cancellation_checkpoint(executed, transaction_index,
                checkpoint, frozen_checkpoint, prior, input.bindings, input.economics,
                &input.signed, account, &input.order, &input.order_siblings, vault,
                membership, successor_membership)
        })
    }

    /// Advance cancellation from an independently pinned predecessor, retaining
    /// the actual native checkpoint and final unspent vault outpoint.
    #[allow(clippy::too_many_arguments)]
    pub fn advance_ecx_cancellation_checkpoint(
        &self,
        executed: &crate::native_child_block_v3::ParentBoundCheckedChildState,
        transaction_index: usize,
        checkpoint: &crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV1,
        frozen_checkpoint: Hash32,
        prior: &ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1,
        bindings: ecx_protocol_core::ecx_configuration_v1::EcxSuccessorBindingsV1,
        economics: ecx_protocol_core::ecx_configuration_v1::EcxConfigurationV1,
        signed: &ecx_protocol_core::ecx_cancel_v1::SignedEcxCancelV1,
        account: ecx_protocol_core::ecx_cash_account_v1::EcxAccountOpeningV1<'_>,
        order: &ecx_protocol_core::ecx_order_v1::EcxAdmittedOrderV2,
        order_siblings: &[Hash32],
        vault: &ecx_proof_core::ecx_execution_v1::EcxTradingVaultWitnessV1<'_>,
        membership: crate::ecx_deposit_membership_v1::EcxCoinMembershipV1<'_>,
        successor_membership: crate::ecx_deposit_membership_v1::EcxCoinMembershipV1<'_>,
    ) -> Result<(ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1,
        crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV1), ecx_proof_core::proof_v2::ProofErrorV2> {
        let invalid = || ecx_proof_core::proof_v2::ProofErrorV2::BindingMismatch(
            "ECX cancellation checkpoint");
        checkpoint.require_frozen(frozen_checkpoint).map_err(|_| invalid())?;
        if checkpoint.execution != self.checkpoint.execution
            || checkpoint.exchange_state_root != prior.digest()?
            || checkpoint.bindings_hash != bindings.digest().map_err(|_| invalid())?
        { return Err(invalid()); }
        let state = self.verify_ecx_cancellation(executed, transaction_index, prior,
            checkpoint.vault_outpoint, bindings, economics, signed, account, order,
            order_siblings, vault, membership, successor_membership)?;
        let next = crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV1 {
            execution: executed.child().next_checkpoint().ok_or_else(invalid)?.clone(),
            exchange_state_root: state.digest()?, bindings_hash: checkpoint.bindings_hash,
            vault_outpoint: successor_membership.leaf.outpoint,
        };
        next.commitment().map_err(|_| invalid())?;
        Ok((state, next))
    }

    /// Final cancellation in a natively executed block. Bind the exact spent
    /// coin, prepared clock, header exchange root and block-end continuing coin.
    /// The outer continuation must authenticate the prior state and policy pins.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_ecx_cancellation(
        &self,
        executed: &crate::native_child_block_v3::ParentBoundCheckedChildState,
        transaction_index: usize,
        prior: &ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1,
        expected_outpoint: elements::OutPoint,
        bindings: ecx_protocol_core::ecx_configuration_v1::EcxSuccessorBindingsV1,
        economics: ecx_protocol_core::ecx_configuration_v1::EcxConfigurationV1,
        signed: &ecx_protocol_core::ecx_cancel_v1::SignedEcxCancelV1,
        account: ecx_protocol_core::ecx_cash_account_v1::EcxAccountOpeningV1<'_>,
        order: &ecx_protocol_core::ecx_order_v1::EcxAdmittedOrderV2,
        order_siblings: &[Hash32],
        vault: &ecx_proof_core::ecx_execution_v1::EcxTradingVaultWitnessV1<'_>,
        membership: crate::ecx_deposit_membership_v1::EcxCoinMembershipV1<'_>,
        successor_membership: crate::ecx_deposit_membership_v1::EcxCoinMembershipV1<'_>,
    ) -> Result<ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1,
        ecx_proof_core::proof_v2::ProofErrorV2> {
        let invalid = || ecx_proof_core::proof_v2::ProofErrorV2::BindingMismatch(
            "ECX cancellation execution context");
        self.check_match_execution_binding(executed.ecx_context(), executed.ecx_checkpoint)
            .map_err(|_| invalid())?;
        let prepared = self.prepare_ecx_match_state(prior, bindings).map_err(|_| invalid())?;
        let child = executed.child();
        if child.next_checkpoint().is_none()
            || child.foundation().block.txdata.get(transaction_index) != Some(vault.successor_transaction)
        { return Err(invalid()); }
        crate::ecx_deposit_membership_v1::check_coin(
            child.transaction_pre_utxo_root(transaction_index).ok_or_else(invalid)?,
            membership, expected_outpoint, vault.source_transaction)?;
        let next = ecx_proof_core::ecx_execution_v1::verify_ecx_cancellation_v1(
            prepared.digest()?, &prepared, expected_outpoint, bindings, economics,
            signed, account, order, order_siblings, vault)?;
        let header = &child.foundation().native_header;
        if header.base.version & crate::native_header_v3::EXCHANGE == 0
            || header.exchange != next.digest()?
        { return Err(invalid()); }
        crate::ecx_deposit_membership_v1::check_coin(child.roots().utxo_root,
            successor_membership, elements::OutPoint {
                txid: vault.successor_transaction.txid(), vout: vault.successor_vout },
            vault.successor_transaction)?;
        Ok(next)
    }

    /// Consume ECXWI1 under a pinned native predecessor. The input opens the
    /// prepared local state; `prior` opens the pre-block checkpoint. These are
    /// deliberately different clock domains and must not be interchanged.
    /// Returns the next continuity record only after native/oracle/vault checks.
    /// The caller still authenticates the checkpoint pin via initialization or
    /// a previous receipt and enforces outstanding-order position reservations.
    #[allow(clippy::too_many_arguments)]
    pub fn advance_ecx_owned_withdrawal<V: ecx_proof_core::ecx_match_input_v1::ConsensusProofVerifier>(
        &self,
        executed: &crate::native_child_block_v3::ParentBoundCheckedChildState,
        transaction_index: usize,
        checkpoint: &crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV1,
        frozen_checkpoint: Hash32,
        prior: &ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1,
        input: &ecx_proof_core::ecx_withdrawal_input_v1::EcxWithdrawalInputV1,
        membership: crate::ecx_deposit_membership_v1::EcxCoinMembershipV1<'_>,
        successor_membership: crate::ecx_deposit_membership_v1::EcxCoinMembershipV1<'_>,
        verifier: &V,
    ) -> Result<(ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1,
        ecx_protocol_core::funding_v2::FundingStateV2,
        crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV1),
        ecx_proof_core::proof_v2::ProofErrorV2>
    {
        let invalid = || ecx_proof_core::proof_v2::ProofErrorV2::BindingMismatch(
            "ECX owned withdrawal checkpoint");
        checkpoint.require_frozen(frozen_checkpoint).map_err(|_| invalid())?;
        if checkpoint.execution != self.checkpoint.execution
            || checkpoint.exchange_state_root != prior.digest()?
            || checkpoint.bindings_hash != input.bindings.digest().map_err(|_| invalid())?
        { return Err(invalid()); }
        let prepared = self.prepare_ecx_match_state(prior, input.bindings)
            .map_err(|_| invalid())?;
        if input.expected_state != prepared.digest()?
            || input.state_bytes != prepared.encode()?
        { return Err(invalid()); }
        let (state, funding) = input.with_decoded_witness(|_, outpoint, account, vault, orders| {
            if outpoint != checkpoint.vault_outpoint { return Err(invalid()); }
            self.verify_ecx_withdrawal(executed, transaction_index, prior,
                checkpoint.vault_outpoint, input.bindings, input.economics,
                &input.configuration, &input.truthcoin, &input.ecx_btc, &input.usdd_usd,
                verifier, &input.funding, &input.signed, account, vault,
                membership, successor_membership, input.recipient_vout, orders)
        })?;
        let next = crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV1 {
            execution: executed.child().next_checkpoint().ok_or_else(invalid)?.clone(),
            exchange_state_root: state.digest()?, bindings_hash: checkpoint.bindings_hash,
            // The membership check pins this exact leaf to the final native
            // UTXO root and the actual successor transaction/output index.
            vault_outpoint: successor_membership.leaf.outpoint,
        };
        next.commitment().map_err(|_| invalid())?;
        Ok((state, funding, next))
    }

    /// Advance a separately authenticated ECX continuity record. The expected
    /// commitment comes from reviewed initialization or a verified prior receipt,
    /// never from hashing an untrusted witness. This is not a recursive proof.
    #[allow(clippy::too_many_arguments)]
    pub fn advance_ecx_match_checkpoint<V: ecx_proof_core::ecx_match_input_v1::ConsensusProofVerifier>(
        &self,
        executed: &crate::native_child_block_v3::ParentBoundCheckedChildState,
        transaction_index: usize,
        checkpoint: &crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV1,
        frozen_checkpoint: Hash32,
        prior: &ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1,
        bindings: ecx_protocol_core::ecx_configuration_v1::EcxSuccessorBindingsV1,
        economics: ecx_protocol_core::ecx_configuration_v1::EcxConfigurationV1,
        journal_bytes: &[u8], proof: &[u8], verifier: &V,
        vault: &ecx_proof_core::ecx_execution_v1::EcxTradingVaultWitnessV1<'_>,
        membership: crate::ecx_deposit_membership_v1::EcxCoinMembershipV1<'_>,
        successor_membership: crate::ecx_deposit_membership_v1::EcxCoinMembershipV1<'_>,
    ) -> Result<(ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1,
        crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV1), ecx_proof_core::proof_v2::ProofErrorV2> {
        let invalid = || ecx_proof_core::proof_v2::ProofErrorV2::BindingMismatch("ECX continuity checkpoint");
        checkpoint.require_frozen(frozen_checkpoint).map_err(|_| invalid())?;
        if checkpoint.execution != self.checkpoint.execution
            || checkpoint.exchange_state_root != prior.digest()?
            || checkpoint.bindings_hash != bindings.digest().map_err(|_| invalid())?
        { return Err(invalid()); }
        let (state, vault_outpoint) = self.verify_ecx_match(executed, transaction_index,
            prior, checkpoint.vault_outpoint, bindings, economics, journal_bytes,
            proof, verifier, vault, membership, successor_membership)?;
        let next = crate::ecx_match_checkpoint_v1::EcxMatchCheckpointV1 {
            execution: executed.child().next_checkpoint().ok_or_else(invalid)?.clone(),
            exchange_state_root: state.digest()?, bindings_hash: checkpoint.bindings_hash,
            vault_outpoint,
        };
        next.commitment().map_err(|_| invalid())?;
        Ok((state, next))
    }

    /// Join one final ECX match to execution under this exact authenticated
    /// context and require its result in the authenticated header's exchange
    /// commitment. Intermediate matches need a separate sequential fold.
    /// The enclosing versioned policy must independently authenticate `bindings`
    /// and the prior vault outpoint. Post-execution membership establishes
    /// unspentness at this block, not at a later tip or parent-chain finality.
    /// This does not install the result in the legacy USDD successor state.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_ecx_match<V: ecx_proof_core::ecx_match_input_v1::ConsensusProofVerifier>(
        &self,
        executed: &crate::native_child_block_v3::ParentBoundCheckedChildState,
        transaction_index: usize,
        prior: &ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1,
        expected_outpoint: elements::OutPoint,
        bindings: ecx_protocol_core::ecx_configuration_v1::EcxSuccessorBindingsV1,
        economics: ecx_protocol_core::ecx_configuration_v1::EcxConfigurationV1,
        journal_bytes: &[u8],
        proof: &[u8],
        verifier: &V,
        vault: &ecx_proof_core::ecx_execution_v1::EcxTradingVaultWitnessV1<'_>,
        membership: crate::ecx_deposit_membership_v1::EcxCoinMembershipV1<'_>,
        successor_membership: crate::ecx_deposit_membership_v1::EcxCoinMembershipV1<'_>,
    ) -> Result<(ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1,
        elements::OutPoint), ecx_proof_core::proof_v2::ProofErrorV2> {
        let invalid = || ecx_proof_core::proof_v2::ProofErrorV2::BindingMismatch("ECX match execution context");
        self.check_match_execution_binding(executed.ecx_context(), executed.ecx_checkpoint)
            .map_err(|_| invalid())?;
        let prepared = self.prepare_ecx_match_state(prior, bindings).map_err(|_| invalid())?;
        let result = crate::ecx_deposit_membership_v1::verify_executed_ecx_match_v1(
            executed, transaction_index, prepared.digest()?, &prepared,
            expected_outpoint, bindings, economics, journal_bytes, proof,
            verifier, vault, membership,
        )?;
        // This is a single final match, not an intermediate block transition.
        // Receipt validity alone cannot authorize a different header state.
        let header = &executed.child().foundation().native_header;
        if header.base.version & crate::native_header_v3::EXCHANGE == 0
            || header.exchange != result.0.digest()?
        { return Err(invalid()); }
        // A transaction may be included and then spent later in the same
        // block. Only the final native root establishes the continuing vault.
        crate::ecx_deposit_membership_v1::check_coin(
            executed.child().roots().utxo_root, successor_membership,
            result.1, vault.successor_transaction,
        )?;
        Ok(result)
    }

    /// Bind a final ordinary withdrawal to the same checked native context as
    /// matches. The outer policy still pins bindings and the prior outpoint and
    /// enforces outstanding-order position reservations. Final UTXO membership
    /// proves block-end unspentness, not later finality. No matcher advance occurs.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_ecx_withdrawal<V: ecx_proof_core::ecx_match_input_v1::ConsensusProofVerifier>(
        &self,
        executed: &crate::native_child_block_v3::ParentBoundCheckedChildState,
        transaction_index: usize,
        prior: &ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1,
        expected_outpoint: elements::OutPoint,
        bindings: ecx_protocol_core::ecx_configuration_v1::EcxSuccessorBindingsV1,
        economics: ecx_protocol_core::ecx_configuration_v1::EcxConfigurationV1,
        configuration: &ecx_protocol_core::FrozenConfigurationV2,
        truthcoin: &ecx_proof_core::ecx_match_input_v1::TruthcoinConsensusProofV1,
        ecx_btc: &ecx_proof_core::ConversionLegConsensusProofV2,
        usdd_usd: &ecx_proof_core::ConversionLegConsensusProofV2,
        verifier: &V,
        funding: &ecx_protocol_core::funding_v2::FundingStateV2,
        signed: &ecx_protocol_core::ecx_withdrawal_v1::SignedEcxWithdrawalV1,
        account: ecx_protocol_core::ecx_cash_account_v1::EcxAccountOpeningV1<'_>,
        vault: &ecx_proof_core::ecx_execution_v1::EcxTradingVaultWitnessV1<'_>,
        membership: crate::ecx_deposit_membership_v1::EcxCoinMembershipV1<'_>,
        successor_membership: crate::ecx_deposit_membership_v1::EcxCoinMembershipV1<'_>,
        recipient_vout: u32,
        records: &[&ecx_protocol_core::ecx_order_v1::EcxAdmittedOrderV2],
    ) -> Result<(ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1,
        ecx_protocol_core::funding_v2::FundingStateV2), ecx_proof_core::proof_v2::ProofErrorV2> {
        let invalid = || ecx_proof_core::proof_v2::ProofErrorV2::BindingMismatch("ECX withdrawal execution context");
        self.check_match_execution_binding(executed.ecx_context(), executed.ecx_checkpoint)
            .map_err(|_| invalid())?;
        let prepared = self.prepare_ecx_match_state(prior, bindings).map_err(|_| invalid())?;
        let child = executed.child();
        if child.foundation().block.txdata.get(transaction_index) != Some(vault.successor_transaction) {
            return Err(invalid());
        }
        crate::ecx_deposit_membership_v1::check_coin(
            child.transaction_pre_utxo_root(transaction_index).ok_or_else(invalid)?,
            membership, expected_outpoint, vault.source_transaction)?;
        let result = ecx_proof_core::ecx_execution_v1::verify_ecx_oracle_withdrawal_v1(
            prepared.digest()?, &prepared, expected_outpoint, bindings, economics,
            configuration, truthcoin, ecx_btc, usdd_usd, verifier, funding,
            signed, account, vault, recipient_vout, records)?;
        let header = &child.foundation().native_header;
        if header.base.version & crate::native_header_v3::EXCHANGE == 0
            || header.exchange != result.0.digest()?
        { return Err(invalid()); }
        crate::ecx_deposit_membership_v1::check_coin(child.roots().utxo_root,
            successor_membership, elements::OutPoint {
                txid: vault.successor_transaction.txid(), vout: vault.successor_vout },
            vault.successor_transaction)?;
        Ok(result)
    }

    fn check_match_execution_binding(
        &self,
        context: Option<ecx_full_consensus_validator_v2::alpha_simplicity_receipt_v3::AlphaExecutionContextV3>,
        checkpoint: Option<Hash32>,
    ) -> Result<(), Error> {
        if context != Some(self.context)
            || checkpoint != Some(self.checkpoint.commitment().map_err(|_| Error::InvalidEnvironment)?)
        { return Err(Error::InvalidEnvironment); }
        Ok(())
    }

    /// Prepare the ECX local match opening for this authenticated P->Q edge.
    /// The prior state must open the checkpoint's actual exchange root. Only
    /// clock fields change; this does not execute funding, alter balances,
    /// authorize a vault spend, or commit the result into a successor block.
    /// Callers must select ECX bindings through their versioned outer policy.
    /// Never apply this to an already proved ECXMJ1 result.
    pub fn prepare_ecx_match_state(
        &self,
        prior: &ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1,
        bindings: ecx_protocol_core::ecx_configuration_v1::EcxSuccessorBindingsV1,
    ) -> Result<ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1, Error> {
        let invalid = || Error::InvalidEnvironment;
        let parent = self.environment.current_bmm_parent.as_ref().ok_or_else(invalid)?;
        let height = u64::from(self.checkpoint.execution.height)
            .checked_add(1).ok_or_else(invalid)?;
        if self.environment.prior_active_root != Some(prior.digest().map_err(|_| invalid())?)
            || prior.bindings_hash != bindings.digest().map_err(|_| invalid())?
            // ECX height comes from the authenticated native checkpoint, not
            // an unrelated USDD capital projection. If present, it must agree.
            || self.environment.projection.as_ref().is_some_and(|p| p.current_sidechain_height != height)
            || prior.sidechain_height >= height
            || parent.height < prior.parent_height
            || parent.median_time_past < prior.parent_mtp
            || (parent.height == prior.parent_height
                && (parent.block_hash_wire != prior.parent_hash
                    || parent.median_time_past != prior.parent_mtp))
        { return Err(invalid()); }
        let mut next = prior.clone();
        next.sidechain_height = height;
        next.parent_hash = parent.block_hash_wire;
        next.parent_height = parent.height;
        next.parent_mtp = parent.median_time_past;
        next.encode().map_err(|_| invalid())?;
        Ok(next)
    }

    /// Derive the block-wide inputs for per-input receipt dispatch. The source
    /// closure is an independent reviewed release input, not a witness claim.
    /// The full V5 checkpoint must be frozen or recursively authenticated by
    /// the caller. Existing opaque V4 evaluator bindings are not reinterpreted.
    pub fn evaluator_scope(
        &self,
        checkpoint: &crate::child_execution_state_v4::ChildExecutionCheckpointV5,
        frozen_checkpoint: Hash32,
        frozen_source_closure: Hash32,
    ) -> Result<ecx_full_consensus_validator_v2::alpha_simplicity_receipt_v3::AlphaEvaluatorScopeV4, Error> {
        if frozen_source_closure == [0; 32] || checkpoint.state != self.checkpoint {
            return Err(Error::InvalidEnvironment);
        }
        let anchor = checkpoint.evaluator_anchor_commitment(frozen_checkpoint)
            .map_err(|_| Error::InvalidEnvironment)?;
        Ok(ecx_full_consensus_validator_v2::alpha_simplicity_receipt_v3::AlphaEvaluatorScopeV4 {
            parent_binding: self.parent_binding,
            child_genesis_internal: self.checkpoint.execution.genesis_internal,
            prior_child_checkpoint: frozen_checkpoint,
            prior_anchor_commitment: anchor,
            source_closure: frozen_source_closure,
            parent_statement: self.context.parent_statement,
            ecx_environment: self.context.ecx_environment,
        })
    }

    pub fn context(&self) -> ecx_full_consensus_validator_v2::alpha_simplicity_receipt_v3::AlphaExecutionContextV3 {
        self.context
    }

    /// Unchanged-root successor carry. The identity is taken from the enclosing
    /// committed source binding, never from an uncommitted capital witness.
    /// This cannot activate a successor or validate a changed exchange root.
    pub fn successor_carry_checkpoint(
        &self,
        executed: &crate::native_child_block_v3::ParentBoundCheckedChildState,
        configuration: &ecx_protocol_core::FrozenConfigurationV2,
        bindings: &crate::capital_genesis_utxos_v4::GenesisStateBindings,
        frozen_bindings: Hash32,
        successor: &crate::child_execution_statement_v4::SuccessorIdentityV4,
        registry: &[ecx_witness_availability::CustodianPublic],
    ) -> Result<crate::child_execution_state_v4::ChildExecutionCheckpointV4, crate::capital_genesis_utxos_v4::GenesisCoinError> {
        use crate::capital_genesis_utxos_v4::GenesisCoinError;
        use crate::child_execution_state_v4::ChildExecutionCheckpointV4;
        let prior = self.checkpoint.capital.as_ref().ok_or(GenesisCoinError::Context)?;
        let bond = self.environment.bond_identity.as_ref().ok_or(GenesisCoinError::Context)?;
        let incremental = self.environment.incremental_identity.as_ref().ok_or(GenesisCoinError::Context)?;
        let parent = self.environment.current_bmm_parent.as_ref().ok_or(GenesisCoinError::Context)?;
        let child = executed.child();
        let next = child.next_checkpoint().ok_or(GenesisCoinError::Context)?;
        let header = &child.foundation().native_header;
        successor.validate().map_err(|_| GenesisCoinError::Context)?;
        configuration.validate().map_err(|_| GenesisCoinError::Context)?;
        if executed.ecx_context() != Some(self.context)
            || executed.ecx_checkpoint != Some(self.checkpoint.commitment().map_err(|_| GenesisCoinError::Context)?)
            || frozen_bindings == [0;32] || bindings.commitment() != frozen_bindings
            || bindings.child_genesis != self.checkpoint.execution.genesis_internal
            || next.height <= bindings.activation_height
            || prior.proof_profile != 1
            || configuration.digest() != bond.configuration_hash
            || successor.configuration_hash == configuration.digest()
            || prior.configuration_hash != successor.configuration_hash
            || prior.transition_program_id != successor.program_id
            || prior.transition_cmr != successor.transition_cmr
            || successor.transition_cmr != incremental.successor_transition_cmr
            || prior.asset_id != configuration.bond_asset_id || prior.asset_id != bond.asset_id
            || prior.deployment_commitment != configuration.bond_deployment_commitment
            || prior.deployment_commitment != bond.deployment_commitment
            || header.base.version & crate::native_header_v3::EXCHANGE == 0
            || header.exchange != prior.exchange_state_root {
            return Err(GenesisCoinError::Context);
        }
        let projection = prior.append_successor_block_sources(
            &child.foundation().block.txdata, u64::from(next.height), parent.height,
            next.tip_internal, configuration, successor.configuration_hash, registry)
            .map_err(|_| GenesisCoinError::State)?;
        let result = ChildExecutionCheckpointV4 { execution: next.clone(), capital: Some(projection) };
        result.checked_header(result.commitment().map_err(|_| GenesisCoinError::State)?, header)
            .map_err(|_| GenesisCoinError::State)?;
        Ok(result)
    }

    /// Carry an already-authenticated finite projection across an executed
    /// block with an unchanged exchange root. This is not a transition verifier:
    /// incremental profiles and changed roots must use their separate paths.
    pub fn finite_carry_checkpoint(
        &self,
        executed: &crate::native_child_block_v3::ParentBoundCheckedChildState,
        configuration: &ecx_protocol_core::FrozenConfigurationV2,
        bindings: &crate::capital_genesis_utxos_v4::GenesisStateBindings,
        frozen_bindings: Hash32,
        registry: &[ecx_witness_availability::CustodianPublic],
    ) -> Result<crate::child_execution_state_v4::ChildExecutionCheckpointV4, crate::capital_genesis_utxos_v4::GenesisCoinError> {
        use crate::capital_genesis_utxos_v4::GenesisCoinError;
        use crate::child_execution_state_v4::ChildExecutionCheckpointV4;
        let prior = self.checkpoint.capital.as_ref().ok_or(GenesisCoinError::Context)?;
        let bond = self.environment.bond_identity.as_ref().ok_or(GenesisCoinError::Context)?;
        let parent = self.environment.current_bmm_parent.as_ref().ok_or(GenesisCoinError::Context)?;
        let child = executed.child();
        let next = child.next_checkpoint().ok_or(GenesisCoinError::Context)?;
        let header = &child.foundation().native_header;
        if executed.ecx_context() != Some(self.context)
            || executed.ecx_checkpoint != Some(self.checkpoint.commitment().map_err(|_| GenesisCoinError::Context)?)
            || frozen_bindings == [0;32] || bindings.commitment() != frozen_bindings
            || bindings.child_genesis != self.checkpoint.execution.genesis_internal
            || next.height <= bindings.activation_height
            || prior.proof_profile != 0
            || prior.configuration_hash != configuration.digest()
            || prior.configuration_hash != bond.configuration_hash
            || prior.asset_id != configuration.bond_asset_id || prior.asset_id != bond.asset_id
            || prior.deployment_commitment != configuration.bond_deployment_commitment
            || prior.deployment_commitment != bond.deployment_commitment
            || prior.transition_program_id != bindings.transition_program_id
            || prior.transition_cmr != bindings.transition_cmr || prior.transition_cmr != bond.transition_cmr
            || header.base.version & crate::native_header_v3::EXCHANGE == 0
            || header.exchange != prior.exchange_state_root {
            return Err(GenesisCoinError::Context);
        }
        configuration.validate().map_err(|_| GenesisCoinError::Context)?;
        let projection = prior.append_finite_block_sources(
            &child.foundation().block.txdata, u64::from(next.height), parent.height,
            next.tip_internal, configuration, registry).map_err(|_| GenesisCoinError::State)?;
        let result = ChildExecutionCheckpointV4 { execution: next.clone(), capital: Some(projection) };
        result.checked_header(result.commitment().map_err(|_| GenesisCoinError::State)?, header)
            .map_err(|_| GenesisCoinError::State)?;
        Ok(result)
    }

    /// Compose verified ECX block execution, frozen genesis validation and the
    /// complete block's finite inbox scan into its successor V4 checkpoint.
    /// Configured receipt verifiers retain their trust/qualification obligations.
    #[allow(clippy::too_many_arguments)]
    pub fn activation_checkpoint(
        &self,
        executed: &crate::native_child_block_v3::ParentBoundCheckedChildState,
        configuration: &ecx_protocol_core::FrozenConfigurationV2,
        bindings: &crate::capital_genesis_utxos_v4::GenesisStateBindings,
        frozen_bindings: Hash32,
        deployment: &ecx_elements_settlement::FrozenBondDeploymentV2,
        genesis: &elements::Transaction,
        inventory: crate::capital_genesis_utxos_v4::ActivationCoinWitness<'_>,
        state: crate::capital_genesis_utxos_v4::ActivationCoinWitness<'_>,
        registry: &[ecx_witness_availability::CustodianPublic],
    ) -> Result<crate::child_execution_state_v4::ChildExecutionCheckpointV4, crate::capital_genesis_utxos_v4::GenesisCoinError> {
        use crate::capital_genesis_utxos_v4::GenesisCoinError;
        use crate::child_execution_state_v4::{CapitalProjectionV4, ChildExecutionCheckpointV4};
        if executed.ecx_context() != Some(self.context)
            || executed.ecx_checkpoint != Some(self.checkpoint.commitment().map_err(|_| GenesisCoinError::Context)?) {
            return Err(GenesisCoinError::Context);
        }
        let child = executed.child();
        let next = child.next_checkpoint().ok_or(GenesisCoinError::Context)?;
        let header = &child.foundation().native_header;
        if next.height != bindings.activation_height
            || header.base.version & crate::native_header_v3::EXCHANGE == 0
            || header.exchange != bindings.state_utxo_root {
            return Err(GenesisCoinError::State);
        }
        let public = self.verify_activation_genesis(executed, configuration, bindings, frozen_bindings,
            deployment, genesis, inventory, state)?;
        let projection = CapitalProjectionV4 {
            proof_profile: 0, exchange_state_root: bindings.state_utxo_root,
            configuration_hash: configuration.digest(), asset_id: configuration.bond_asset_id,
            deployment_commitment: configuration.bond_deployment_commitment,
            transition_program_id: bindings.transition_program_id, transition_cmr: bindings.transition_cmr,
            covenant_state_hash: public.state_hash(bindings.public_state_domain),
            covenant_inbox_root: public.bond_inbox_head_root,
            covenant_inbox_count: u128::from(public.bond_inbox_entry_count),
            node_inbox_root: public.bond_inbox_head_root,
            node_inbox_count: u128::from(public.bond_inbox_entry_count),
        }.append_finite_block_sources(&child.foundation().block.txdata, u64::from(next.height),
            self.environment.current_bmm_parent.as_ref().ok_or(GenesisCoinError::Context)?.height,
            next.tip_internal, configuration, registry).map_err(|_| GenesisCoinError::State)?;
        let result = ChildExecutionCheckpointV4 { execution: next.clone(), capital: Some(projection) };
        result.checked_header(result.commitment().map_err(|_| GenesisCoinError::State)?, header)
            .map_err(|_| GenesisCoinError::State)?;
        Ok(result)
    }

    /// Native activation checks use the post-execution coin view, but the
    /// authenticated predecessor P clock. Require the ECX execution result
    /// from this exact checkpoint/context; a pre-block membership is insufficient.
    /// The release binding is an independent trust input. No inbox scan here.
    pub fn verify_activation_genesis(
        &self,
        executed: &crate::native_child_block_v3::ParentBoundCheckedChildState,
        configuration: &ecx_protocol_core::FrozenConfigurationV2,
        bindings: &crate::capital_genesis_utxos_v4::GenesisStateBindings,
        frozen_bindings: Hash32,
        deployment: &ecx_elements_settlement::FrozenBondDeploymentV2,
        genesis: &elements::Transaction,
        inventory: crate::capital_genesis_utxos_v4::ActivationCoinWitness<'_>,
        state: crate::capital_genesis_utxos_v4::ActivationCoinWitness<'_>,
    ) -> Result<ecx_proof_core::CovenantPublicStateV2, crate::capital_genesis_utxos_v4::GenesisCoinError> {
        use crate::capital_genesis_utxos_v4::{GenesisCoinError, verify_derived_activation_coins};
        let bond = self.environment.bond_identity.as_ref().ok_or(GenesisCoinError::Context)?;
        let parent = self.environment.current_bmm_parent.as_ref().ok_or(GenesisCoinError::Context)?;
        if executed.ecx_context() != Some(self.context)
            || executed.ecx_checkpoint != Some(self.checkpoint.commitment().map_err(|_| GenesisCoinError::Context)?)
            || frozen_bindings == [0;32] || bindings.commitment() != frozen_bindings
            || self.checkpoint.capital.is_some()
            || bindings.child_genesis != self.checkpoint.execution.genesis_internal
            || configuration.digest() != bond.configuration_hash
            || configuration.bond_asset_id != bond.asset_id
            || configuration.bond_deployment_commitment != bond.deployment_commitment
            || bindings.transition_cmr != bond.transition_cmr {
            return Err(GenesisCoinError::Context);
        }
        let height = self.checkpoint.execution.height.checked_add(1).ok_or(GenesisCoinError::Context)?;
        verify_derived_activation_coins(executed.child().roots().utxo_root,
            height, parent.median_time_past, configuration, bindings,
            deployment, genesis, inventory, state)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn authenticate<P: crate::FullAlphaReceiptVerifierV3>(
        environment: &EcxExecutionEnvironmentV1,
        frozen_environment: Hash32,
        frozen_evaluator_binding: Hash32,
        checkpoint: &crate::child_execution_state_v4::ChildExecutionCheckpointV4,
        frozen_checkpoint: Hash32,
        prior_header: &crate::native_header_v3::NativeHeader,
        parent: &crate::conversion_parent_link_v3::AlphaConversionParentLinkInputV3,
        frozen_parent_binding: Hash32,
        verifier: &P,
    ) -> Result<Self, Error> {
        if [frozen_environment, frozen_evaluator_binding, frozen_parent_binding].contains(&[0; 32])
            || environment.commitment()? != frozen_environment
            || parent.binding.commitment().map_err(|_| Error::InvalidEnvironment)? != frozen_parent_binding
            || parent.binding.child_genesis_hash_internal != checkpoint.execution.genesis_internal
            || parent.binding.child_consensus_configuration_commitment != checkpoint.execution.configuration_commitment
            || parent.binding.child_checkpoint_hash_internal != checkpoint.execution.tip_internal
            || parent.binding.child_checkpoint_height != checkpoint.execution.height {
            return Err(Error::InvalidEnvironment);
        }
        let mut derived = environment.clone();
        derived.bind_checkpoint_projection(checkpoint, frozen_checkpoint, prior_header)?;
        let verified = crate::conversion_parent_link_v3::execute_alpha_conversion_parent_link_v3(parent, verifier)
            .map_err(|_| Error::InvalidEnvironment)?;
        // Native execution uses predecessor P, never the mining block Q's clock.
        derived.current_bmm_parent = Some(Parent {
            block_hash_wire: verified.parent_predecessor_hash_internal,
            height: u64::from(parent.terminal_parent_predecessor.tip.height),
            median_time_past: u64::from(ecx_full_consensus_validator_v2::median_time_past_v2(
                &parent.terminal_parent_predecessor.pow_context.previous_11_times)
                .map_err(|_| Error::InvalidEnvironment)?),
        });
        if &derived != environment { return Err(Error::InvalidEnvironment); }
        derived.validate()?;
        use bitcoin::hashes::{sha256, Hash as _};
        Ok(Self { checkpoint: checkpoint.clone(), environment: derived,
            parent_binding: frozen_parent_binding,
            context: ecx_full_consensus_validator_v2::alpha_simplicity_receipt_v3::AlphaExecutionContextV3 {
            evaluator_binding: frozen_evaluator_binding,
            parent_statement: sha256::Hash::hash(&verified.canonical_bytes()).to_byte_array(),
            ecx_environment: frozen_environment,
        } })
    }
}

/// Custody counterpart: no legacy economic checkpoint is manufactured.
/// Capital transition validation remains an enclosing guest obligation.
pub struct CheckedAlphaCustodyExecutionContextV4 {
    context: ecx_full_consensus_validator_v2::alpha_simplicity_receipt_v3::AlphaExecutionContextV3,
    checkpoint: crate::child_custody_checkpoint_v3::ChildCustodyExecutionCheckpointV4,
    environment: EcxExecutionEnvironmentV1,
    parent_binding: Hash32,
}

impl CheckedAlphaCustodyExecutionContextV4 {
    /// Carry only an unchanged, previously authenticated capital root. The
    /// caller must join the returned projection to the authenticated parent
    /// endpoint; this neither activates a successor nor proves a changed root.
    pub fn carry_projection(
        &self,
        executed: &crate::native_child_block_v3::ParentBoundCheckedCustodyStateV3,
        configuration: &ecx_protocol_core::FrozenConfigurationV2,
        bindings: &crate::capital_genesis_utxos_v4::GenesisStateBindings,
        frozen_bindings: Hash32,
        successor: Option<&crate::child_execution_statement_v4::SuccessorIdentityV4>,
        registry: &[ecx_witness_availability::CustodianPublic],
    ) -> Result<crate::child_execution_state_v4::CapitalProjectionV4, crate::capital_genesis_utxos_v4::GenesisCoinError> {
        use crate::capital_genesis_utxos_v4::GenesisCoinError as E;
        let prior = self.checkpoint.capital.as_ref().ok_or(E::Context)?;
        let bond = self.environment.bond_identity.as_ref().ok_or(E::Context)?;
        let parent = self.environment.current_bmm_parent.as_ref().ok_or(E::Context)?;
        let child = executed.child();
        let next = child.next_checkpoint().ok_or(E::Context)?;
        let header = &child.foundation().native_header;
        configuration.validate().map_err(|_| E::Context)?;
        if executed.ecx_context != Some(self.context)
            || executed.ecx_checkpoint != Some(self.checkpoint.commitment().map_err(|_| E::Context)?)
            || frozen_bindings == [0;32] || bindings.commitment() != frozen_bindings
            || bindings.child_genesis != self.checkpoint.execution.genesis_internal
            || next.genesis_internal != bindings.child_genesis
            || next.height != self.checkpoint.execution.height.checked_add(1).ok_or(E::Context)?
            || next.height <= bindings.activation_height
            || configuration.digest() != bond.configuration_hash
            || prior.asset_id != configuration.bond_asset_id || prior.asset_id != bond.asset_id
            || prior.deployment_commitment != configuration.bond_deployment_commitment
            || prior.deployment_commitment != bond.deployment_commitment
            || header.base.version & crate::native_header_v3::EXCHANGE == 0
            || header.exchange != prior.exchange_state_root {
            return Err(E::Context);
        }
        match successor {
            None => {
                if prior.proof_profile != 0
                    || prior.configuration_hash != configuration.digest()
                    || prior.transition_program_id != bindings.transition_program_id
                    || prior.transition_cmr != bindings.transition_cmr
                    || prior.transition_cmr != bond.transition_cmr {
                    return Err(E::Context);
                }
                prior.append_finite_block_sources(&child.foundation().block.txdata,
                    u64::from(next.height), parent.height, next.tip_internal,
                    configuration, registry).map_err(|_| E::State)
            }
            Some(successor) => {
                successor.validate().map_err(|_| E::Context)?;
                let incremental = self.environment.incremental_identity.as_ref().ok_or(E::Context)?;
                if prior.proof_profile != 1
                    || successor.configuration_hash == configuration.digest()
                    || prior.configuration_hash != successor.configuration_hash
                    || prior.transition_program_id != successor.program_id
                    || prior.transition_cmr != successor.transition_cmr
                    || successor.transition_cmr != incremental.successor_transition_cmr {
                    return Err(E::Context);
                }
                prior.append_successor_block_sources(&child.foundation().block.txdata,
                    u64::from(next.height), parent.height, next.tip_internal,
                    configuration, successor.configuration_hash, registry).map_err(|_| E::State)
            }
        }
    }

    /// Derive activation capital only after genesis membership and the entire
    /// executed block's source scan. The caller must join the authenticated
    /// parent endpoint to form the full successor custody checkpoint.
    #[allow(clippy::too_many_arguments)]
    pub fn activation_projection(
        &self,
        executed: &crate::native_child_block_v3::ParentBoundCheckedCustodyStateV3,
        configuration: &ecx_protocol_core::FrozenConfigurationV2,
        bindings: &crate::capital_genesis_utxos_v4::GenesisStateBindings,
        frozen_bindings: Hash32,
        deployment: &ecx_elements_settlement::FrozenBondDeploymentV2,
        genesis: &elements::Transaction,
        inventory: crate::capital_genesis_utxos_v4::ActivationCoinWitness<'_>,
        state: crate::capital_genesis_utxos_v4::ActivationCoinWitness<'_>,
        registry: &[ecx_witness_availability::CustodianPublic],
        initialization: crate::genesis_initialization_v2::CheckedGenesisInitialization,
    ) -> Result<crate::child_execution_state_v4::CapitalProjectionV4, crate::capital_genesis_utxos_v4::GenesisCoinError> {
        use crate::capital_genesis_utxos_v4::GenesisCoinError;
        use crate::child_execution_state_v4::CapitalProjectionV4;
        let child = executed.child();
        let next = child.next_checkpoint().ok_or(GenesisCoinError::Context)?;
        let header = &child.foundation().native_header;
        if next.height != bindings.activation_height
            || header.base.version & crate::native_header_v3::EXCHANGE == 0
            || header.exchange != bindings.state_utxo_root {
            return Err(GenesisCoinError::State);
        }
        let public = self.verify_activation_genesis(executed, configuration, bindings,
            frozen_bindings, deployment, genesis, inventory, state, initialization)?;
        CapitalProjectionV4 {
            proof_profile: 0, exchange_state_root: bindings.state_utxo_root,
            configuration_hash: configuration.digest(), asset_id: configuration.bond_asset_id,
            deployment_commitment: configuration.bond_deployment_commitment,
            transition_program_id: bindings.transition_program_id, transition_cmr: bindings.transition_cmr,
            covenant_state_hash: public.state_hash(bindings.public_state_domain),
            covenant_inbox_root: public.bond_inbox_head_root,
            covenant_inbox_count: u128::from(public.bond_inbox_entry_count),
            node_inbox_root: public.bond_inbox_head_root,
            node_inbox_count: u128::from(public.bond_inbox_entry_count),
        }.append_finite_block_sources(&child.foundation().block.txdata, u64::from(next.height),
            self.environment.current_bmm_parent.as_ref().ok_or(GenesisCoinError::Context)?.height,
            next.tip_internal, configuration, registry).map_err(|_| GenesisCoinError::State)
    }

    /// Check genesis coins against the executed custody UTXO root. The full
    /// checkpoint/context markers prohibit substituting a raw block result or
    /// a result from another authenticated session. This does not scan inboxes
    /// or produce an authenticated successor capital checkpoint.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_activation_genesis(
        &self,
        executed: &crate::native_child_block_v3::ParentBoundCheckedCustodyStateV3,
        configuration: &ecx_protocol_core::FrozenConfigurationV2,
        bindings: &crate::capital_genesis_utxos_v4::GenesisStateBindings,
        frozen_bindings: Hash32,
        deployment: &ecx_elements_settlement::FrozenBondDeploymentV2,
        genesis: &elements::Transaction,
        inventory: crate::capital_genesis_utxos_v4::ActivationCoinWitness<'_>,
        state: crate::capital_genesis_utxos_v4::ActivationCoinWitness<'_>,
        initialization: crate::genesis_initialization_v2::CheckedGenesisInitialization,
    ) -> Result<ecx_proof_core::CovenantPublicStateV2, crate::capital_genesis_utxos_v4::GenesisCoinError> {
        use crate::capital_genesis_utxos_v4::{GenesisCoinError, verify_checkpoint_public_activation_coins};
        let bond = self.environment.bond_identity.as_ref().ok_or(GenesisCoinError::Context)?;
        let parent = self.environment.current_bmm_parent.as_ref().ok_or(GenesisCoinError::Context)?;
        if executed.ecx_context != Some(self.context)
            || executed.ecx_checkpoint != Some(self.checkpoint.commitment().map_err(|_| GenesisCoinError::Context)?)
            || frozen_bindings == [0;32] || bindings.commitment() != frozen_bindings
            || self.checkpoint.capital.is_some()
            || bindings.child_genesis != self.checkpoint.execution.genesis_internal
            || configuration.digest() != bond.configuration_hash
            || configuration.bond_asset_id != bond.asset_id
            || configuration.bond_deployment_commitment != bond.deployment_commitment
            || bindings.transition_cmr != bond.transition_cmr {
            return Err(GenesisCoinError::Context);
        }
        let height = self.checkpoint.execution.height.checked_add(1).ok_or(GenesisCoinError::Context)?;
        let next = executed.child().next_checkpoint().ok_or(GenesisCoinError::Context)?;
        if next.height != height || next.genesis_internal != bindings.child_genesis {
            return Err(GenesisCoinError::Context);
        }
        verify_checkpoint_public_activation_coins(executed.child().roots().utxo_root,
            height, parent.median_time_past, configuration, bindings,
            deployment, genesis, inventory, state, initialization)
    }

    pub fn context(&self) -> ecx_full_consensus_validator_v2::alpha_simplicity_receipt_v3::AlphaExecutionContextV3 {
        self.context
    }
    pub fn environment(&self) -> &EcxExecutionEnvironmentV1 { &self.environment }
    pub fn evaluator_scope(&self, frozen_checkpoint: Hash32, frozen_source_closure: Hash32)
        -> Result<ecx_full_consensus_validator_v2::alpha_simplicity_receipt_v3::AlphaEvaluatorScopeV4, Error> {
        if frozen_source_closure == [0;32] { return Err(Error::InvalidEnvironment); }
        let anchor = self.checkpoint.evaluator_anchor_commitment(frozen_checkpoint)
            .map_err(|_| Error::InvalidEnvironment)?;
        Ok(ecx_full_consensus_validator_v2::alpha_simplicity_receipt_v3::AlphaEvaluatorScopeV4 {
            parent_binding: self.parent_binding,
            child_genesis_internal: self.checkpoint.execution.genesis_internal,
            prior_child_checkpoint: frozen_checkpoint, prior_anchor_commitment: anchor,
            source_closure: frozen_source_closure,
            parent_statement: self.context.parent_statement,
            ecx_environment: self.context.ecx_environment,
        })
    }
    #[allow(clippy::too_many_arguments)]
    pub fn authenticate<P: crate::FullAlphaReceiptVerifierV3>(
        environment: &EcxExecutionEnvironmentV1, frozen_environment: Hash32,
        frozen_evaluator_binding: Hash32,
        checkpoint: &crate::child_custody_checkpoint_v3::ChildCustodyExecutionCheckpointV4,
        frozen_checkpoint: Hash32, prior_header: &crate::native_header_v3::NativeHeader,
        parent: &crate::conversion_parent_link_v3::AlphaConversionParentLinkInputV3,
        frozen_parent_binding: Hash32, verifier: &P,
    ) -> Result<Self, Error> {
        if [frozen_environment, frozen_evaluator_binding, frozen_parent_binding].contains(&[0;32])
            || environment.commitment()? != frozen_environment
            || parent.binding.commitment().map_err(|_| Error::InvalidEnvironment)? != frozen_parent_binding
            || parent.binding.child_genesis_hash_internal != checkpoint.execution.genesis_internal
            || parent.binding.child_consensus_configuration_commitment != checkpoint.execution.configuration_commitment
            || parent.binding.child_checkpoint_hash_internal != checkpoint.execution.tip_internal
            || parent.binding.child_checkpoint_height != checkpoint.execution.height {
            return Err(Error::InvalidEnvironment);
        }
        let mut derived = environment.clone();
        derived.bind_custody_checkpoint_projection(checkpoint, frozen_checkpoint, prior_header)?;
        let verified = crate::conversion_parent_link_v3::execute_alpha_conversion_parent_link_v3(parent, verifier)
            .map_err(|_| Error::InvalidEnvironment)?;
        derived.current_bmm_parent = Some(Parent {
            block_hash_wire: verified.parent_predecessor_hash_internal,
            height: u64::from(parent.terminal_parent_predecessor.tip.height),
            median_time_past: u64::from(ecx_full_consensus_validator_v2::median_time_past_v2(
                &parent.terminal_parent_predecessor.pow_context.previous_11_times)
                .map_err(|_| Error::InvalidEnvironment)?),
        });
        if &derived != environment { return Err(Error::InvalidEnvironment); }
        derived.validate()?;
        use bitcoin::hashes::{sha256, Hash as _};
        Ok(Self { checkpoint: checkpoint.clone(), environment: derived, parent_binding: frozen_parent_binding,
            context: ecx_full_consensus_validator_v2::alpha_simplicity_receipt_v3::AlphaExecutionContextV3 {
                evaluator_binding: frozen_evaluator_binding,
                parent_statement: sha256::Hash::hash(&verified.canonical_bytes()).to_byte_array(),
                ecx_environment: frozen_environment,
            } })
    }
}

impl EcxExecutionEnvironmentV1 {
    /// Atomic binding from a separately frozen full custody checkpoint.
    /// Header roots and node inbox values are derived, never host overrides.
    pub fn bind_custody_checkpoint_projection(&mut self,
        checkpoint: &crate::child_custody_checkpoint_v3::ChildCustodyExecutionCheckpointV4,
        expected_checkpoint: Hash32, header: &crate::native_header_v3::NativeHeader,
    ) -> Result<(), Error> {
        checkpoint.checked_header(expected_checkpoint, header).map_err(|_| Error::InvalidEnvironment)?;
        self.bind_checked_projection(checkpoint.capital.as_ref(), checkpoint.execution.tip_internal,
            checkpoint.execution.height, header)
    }
    /// Bind header roots and the native NODE inbox projection to one frozen V4
    /// checkpoint. Expected commitment must be independently frozen or verified
    /// through a preceding receipt. This does not authenticate the separately
    /// supplied bond/program identities or the current BMM parent.
    /// Failure is atomic; absent capital clears any stale projection.
    pub fn bind_checkpoint_projection(
        &mut self,
        checkpoint: &crate::child_execution_state_v4::ChildExecutionCheckpointV4,
        expected_checkpoint: Hash32,
        header: &crate::native_header_v3::NativeHeader,
    ) -> Result<(), Error> {
        checkpoint.checked_header(expected_checkpoint, header)
            .map_err(|_| Error::InvalidEnvironment)?;
        self.bind_checked_projection(checkpoint.capital.as_ref(), checkpoint.execution.tip_internal,
            checkpoint.execution.height, header)
    }

    fn bind_checked_projection(&mut self,
        capital: Option<&crate::child_execution_state_v4::CapitalProjectionV4>,
        tip: Hash32, height: u32, header: &crate::native_header_v3::NativeHeader,
    ) -> Result<(), Error> {
        let projection = capital.map(|capital| {
            Ok(Projection {
                prior_active_bond_inbox_root: capital.node_inbox_root,
                prior_active_bond_inbox_count: u64::try_from(capital.node_inbox_count)
                    .map_err(|_| Error::InvalidEnvironment)?,
                current_sidechain_height: u64::from(height)
                    .checked_add(1).ok_or(Error::InvalidEnvironment)?,
            })
        }).transpose()?;
        let mut next = self.clone();
        next.bind_prior_child_header(header, tip, height)?;
        next.projection = projection;
        next.validate()?;
        *self = next;
        Ok(())
    }

    /// Authenticate the checkpoint preimage before deriving the header fields.
    /// `expected_checkpoint` must come from the frozen source policy or a
    /// verified preceding receipt, never from the witness being checked.
    pub fn bind_checkpoint_header(
        &mut self,
        checkpoint: &crate::child_execution_state_v3::ChildExecutionCheckpointV3,
        expected_checkpoint: Hash32,
        header: &crate::native_header_v3::NativeHeader,
    ) -> Result<(), Error> {
        checkpoint.require_frozen(expected_checkpoint)
            .map_err(|_| Error::InvalidEnvironment)?;
        self.bind_prior_child_header(header, checkpoint.tip_internal, checkpoint.height)
    }

    /// Replace only the prior-header fields using a header bound to an
    /// independently verified child checkpoint. Parent, configuration and
    /// bond projection authentication remain separate required checks.
    /// Failure leaves this environment unchanged.
    pub fn bind_prior_child_header(
        &mut self,
        header: &crate::native_header_v3::NativeHeader,
        authenticated_tip: Hash32,
        authenticated_height: u32,
    ) -> Result<(), Error> {
        let context = header.prior_exchange_context(authenticated_tip, authenticated_height)
            .map_err(|_| Error::InvalidEnvironment)?;
        self.prior_active_root = context.as_ref().map(|c| c.exchange);
        self.forced_inbox_root = context.as_ref().map(|c| c.forced);
        self.deposit_inbox_root = context.as_ref().map(|c| c.deposit);
        self.forced_processed_cursor = context.as_ref().map_or(0, |c| c.forced_cursor);
        self.deposit_processed_cursor = context.as_ref().map_or(0, |c| c.deposit_cursor);
        Ok(())
    }

    /// Mirrors the native exec.c optional-field validation. Cursor values are
    /// not forced to zero when inbox roots are absent: native does not impose
    /// that rule here. Their semantic validity belongs to the enclosing child.
    pub fn validate(&self) -> Result<(), Error> {
        let zero = [0; 32];
        if [self.prior_active_root, self.forced_inbox_root, self.deposit_inbox_root]
            .into_iter().flatten().any(|h| h == zero)
            || self.current_bmm_parent.as_ref().is_some_and(|p|
                p.block_hash_wire == zero || p.height == 0 || p.median_time_past == 0)
            || self.bond_identity.as_ref().is_some_and(|b| b.hashes().contains(&zero))
            || self.incremental_identity.as_ref().is_some_and(|i|
                self.bond_identity.is_none() || i.activation_cmr == zero || i.successor_transition_cmr == zero)
            || self.projection.as_ref().is_some_and(|p|
                p.prior_active_bond_inbox_root == zero || p.current_sidechain_height == 0) {
            return Err(Error::InvalidEnvironment);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut out = MAGIC.to_vec();
        for root in [self.prior_active_root, self.forced_inbox_root, self.deposit_inbox_root] {
            out.push(u8::from(root.is_some()));
            out.extend_from_slice(&root.unwrap_or([0; 32]));
        }
        out.extend_from_slice(&self.forced_processed_cursor.to_be_bytes());
        out.extend_from_slice(&self.deposit_processed_cursor.to_be_bytes());
        out.push(u8::from(self.current_bmm_parent.is_some()));
        let parent = self.current_bmm_parent.as_ref();
        out.extend_from_slice(&parent.map_or([0; 32], |p| p.block_hash_wire));
        out.extend_from_slice(&parent.map_or(0, |p| p.height).to_be_bytes());
        out.extend_from_slice(&parent.map_or(0, |p| p.median_time_past).to_be_bytes());
        out.push(u8::from(self.bond_identity.is_some()));
        for hash in self.bond_identity.as_ref().map_or([[0; 32]; 8], BondIdentity::hashes) {
            out.extend_from_slice(&hash);
        }
        out.push(u8::from(self.incremental_identity.is_some()));
        out.extend_from_slice(&self.incremental_identity.as_ref().map_or([0; 32], |i| i.activation_cmr));
        out.extend_from_slice(&self.incremental_identity.as_ref().map_or([0; 32], |i| i.successor_transition_cmr));
        out.push(u8::from(self.projection.is_some()));
        out.extend_from_slice(&self.projection.as_ref().map_or([0; 32], |p| p.prior_active_bond_inbox_root));
        out.extend_from_slice(&self.projection.as_ref().map_or(0, |p| p.prior_active_bond_inbox_count).to_be_bytes());
        out.extend_from_slice(&self.projection.as_ref().map_or(0, |p| p.current_sidechain_height).to_be_bytes());
        debug_assert_eq!(out.len(), ENCODED_LENGTH);
        Ok(out)
    }

    pub fn commitment(&self) -> Result<Hash32, Error> {
        Ok(tagged_hash("ECX/native-execution-environment/v1", &self.encode()?))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != ENCODED_LENGTH || &bytes[..8] != MAGIC {
            return Err(Error::NonCanonical);
        }
        let mut reader = Reader { bytes: &bytes[8..] };
        let prior_active_root = reader.root()?;
        let forced_inbox_root = reader.root()?;
        let deposit_inbox_root = reader.root()?;
        let forced_processed_cursor = reader.number();
        let deposit_processed_cursor = reader.number();
        let flag = reader.flag()?;
        let parent = Parent { block_hash_wire: reader.take(), height: reader.number(), median_time_past: reader.number() };
        let current_bmm_parent = flag.then_some(parent);
        let flag = reader.flag()?;
        let bond = BondIdentity {
            configuration_hash: reader.take(), asset_id: reader.take(), deployment_commitment: reader.take(),
            transition_cmr: reader.take(), collateral_vault_script_sha256: reader.take(), collateral_vault_cmr: reader.take(),
            insurance_reserve_script_sha256: reader.take(), insurance_reserve_cmr: reader.take(),
        };
        let bond_identity = flag.then_some(bond);
        let flag = reader.flag()?;
        let incremental = IncrementalIdentity { activation_cmr: reader.take(), successor_transition_cmr: reader.take() };
        let incremental_identity = flag.then_some(incremental);
        let flag = reader.flag()?;
        let projection = Projection { prior_active_bond_inbox_root: reader.take(), prior_active_bond_inbox_count: reader.number(), current_sidechain_height: reader.number() };
        let value = Self { prior_active_root, forced_inbox_root, deposit_inbox_root, forced_processed_cursor,
            deposit_processed_cursor, current_bmm_parent, bond_identity, incremental_identity, projection: flag.then_some(projection) };
        // Reject nonzero bytes hidden behind absence flags as native does.
        if value.encode()? != bytes { return Err(Error::NonCanonical); }
        Ok(value)
    }
}

// Fixed-length input was checked before constructing the reader; no variable
// lengths are taken from the wire.
struct Reader<'a> { bytes: &'a [u8] }
impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> [u8; N] {
        let (value, rest) = self.bytes.split_at(N);
        self.bytes = rest;
        value.try_into().expect("fixed-length codec")
    }
    fn number(&mut self) -> u64 { u64::from_be_bytes(self.take()) }
    fn flag(&mut self) -> Result<bool, Error> {
        match self.take::<1>()[0] { 0 => Ok(false), 1 => Ok(true), _ => Err(Error::NonCanonical) }
    }
    fn root(&mut self) -> Result<Option<Hash32>, Error> {
        let flag = self.flag()?;
        let hash = self.take();
        if !flag && hash != [0; 32] { return Err(Error::NonCanonical); }
        Ok(flag.then_some(hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn v4_projection_binds_node_head_rejects_substitution_and_never_truncates() {
        use crate::{child_execution_state_v3::ChildExecutionCheckpointV3,
            child_execution_state_v4::{ChildExecutionCheckpointV4, CapitalProjectionV4},
            native_header_v3::*, native_withdrawal_accumulator_v3::WithdrawalAccumulator};
        use ecx_full_consensus_validator_v2::elements_v2::*;
        use elements::hashes::Hash as _;
        let mut header = NativeHeader::from_standard(elements::BlockHeader {
            version: EXCHANGE | FORCED | DEPOSIT | CURSORS,
            prev_blockhash: elements::BlockHash::from_byte_array([1; 32]),
            merkle_root: elements::TxMerkleNode::from_byte_array([2; 32]),
            time: 100, height: 7, ext: elements::BlockExtData::Proof {
                challenge: elements::Script::from(vec![0x51]), solution: elements::Script::new(),
            },
        });
        header.exchange = [1; 32]; header.forced = [2; 32]; header.deposit = [3; 32];
        let mut checkpoint = ChildExecutionCheckpointV4 {
            execution: ChildExecutionCheckpointV3 {
                genesis_internal: [4; 32], configuration_commitment: [5; 32],
                tip_internal: header.hash_internal().unwrap(), height: 7,
                history_commitment: [6; 32], spent_claims_root: [7; 32],
                withdrawals: WithdrawalAccumulator::empty(),
                roots: ElementsTransactionStateRootsV2 {
                    utxo_root: ElementsSparseUtxoNodeV2 { hash: [8; 32],
                        aggregate: ElementsUtxoAggregateV2 { count: 0 } },
                    economic_root: ElementsSparseEconomicNodeV2 { hash: [9; 32],
                        aggregate: ElementsEconomicAggregateV2 { count: 0,
                            outstanding_base_atoms: 0, redeemable_reserve_quote_atoms: 0 } },
                },
            },
            capital: Some(CapitalProjectionV4 { proof_profile: 0, exchange_state_root: [1; 32],
                configuration_hash: [2; 32], asset_id: [3; 32], deployment_commitment: [4; 32],
                transition_program_id: [5; 32], transition_cmr: [6; 32], covenant_state_hash: [7; 32],
                covenant_inbox_root: [8; 32], covenant_inbox_count: 2,
                node_inbox_root: [9; 32], node_inbox_count: 3 }),
        };
        let frozen = checkpoint.commitment().unwrap();
        let custody_checkpoint = crate::child_custody_checkpoint_v3::ChildCustodyExecutionCheckpointV4 {
            execution: crate::child_custody_checkpoint_v3::ChildCustodyCheckpointV3 {
                genesis_internal: checkpoint.execution.genesis_internal,
                configuration_commitment: checkpoint.execution.configuration_commitment,
                tip_internal: checkpoint.execution.tip_internal, height: checkpoint.execution.height,
                history_commitment: checkpoint.execution.history_commitment,
                spent_claims_root: checkpoint.execution.spent_claims_root,
                withdrawals: checkpoint.execution.withdrawals.clone(),
                classification: ElementsCustodyClassificationV3 {
                    native_pegged_asset_id: [30;32], custody_asset_id: [31;32],
                },
                roots: ElementsTransactionCustodyRootsV3 {
                    utxo_root: checkpoint.execution.roots.utxo_root,
                    custody_root: ElementsSparseCustodyNodeV3 { hash: [32;32], count: 0, custody_supply_atoms: 0 },
                },
            }, capital: checkpoint.capital.clone(), bmm_endpoint: Some(vec![1;80]),
        };
        let frozen_custody = custody_checkpoint.commitment().unwrap();
        let mut environment = EcxExecutionEnvironmentV1::default();
        environment.bind_checkpoint_projection(&checkpoint, frozen, &header).unwrap();
        let mut custody_environment = EcxExecutionEnvironmentV1::default();
        custody_environment.bind_custody_checkpoint_projection(&custody_checkpoint, frozen_custody, &header).unwrap();
        assert_eq!(custody_environment, environment);
        assert!(custody_environment.bind_custody_checkpoint_projection(&custody_checkpoint, frozen, &header).is_err());
        assert_eq!(custody_environment, environment);
        let mut wide = custody_checkpoint.clone();
        wide.capital.as_mut().unwrap().proof_profile = 1;
        wide.capital.as_mut().unwrap().node_inbox_count = u64::MAX as u128 + 1;
        assert!(custody_environment.bind_custody_checkpoint_projection(&wide, wide.commitment().unwrap(), &header).is_err());
        assert_eq!(custody_environment, environment);
        let mut empty = custody_checkpoint.clone(); empty.capital = None;
        custody_environment.bind_custody_checkpoint_projection(&empty, empty.commitment().unwrap(), &header).unwrap();
        assert!(custody_environment.projection.is_none());
        // Scope-only regression: synthetic checked context, not receipt evidence.
        let checked = CheckedAlphaExecutionContextV4 {
            checkpoint: checkpoint.clone(), environment: environment.clone(),
            parent_binding: [10; 32],
            context: ecx_full_consensus_validator_v2::alpha_simplicity_receipt_v3::AlphaExecutionContextV3 {
                evaluator_binding: [11; 32], parent_statement: [12; 32], ecx_environment: [13; 32],
            },
        };
        let anchored = crate::child_execution_state_v4::ChildExecutionCheckpointV5 {
            state: checkpoint.clone(), bmm_endpoint: Some(vec![1; 80]),
        };
        let anchored_hash = anchored.commitment().unwrap();
        let scope = checked.evaluator_scope(&anchored, anchored_hash, [14; 32]).unwrap();
        assert_eq!(scope.parent_binding, [10; 32]);
        assert_eq!(scope.parent_statement, [12; 32]);
        assert_eq!(scope.ecx_environment, [13; 32]);
        assert_eq!(scope.source_closure, [14; 32]);
        assert_eq!(scope.prior_child_checkpoint, anchored_hash);
        assert_eq!(scope.child_genesis_internal, checkpoint.execution.genesis_internal);
        assert_eq!(scope.prior_anchor_commitment,
            anchored.evaluator_anchor_commitment(anchored_hash).unwrap());
        assert!(checked.evaluator_scope(&anchored, frozen, [14; 32]).is_err());
        assert!(checked.evaluator_scope(&anchored, anchored_hash, [0; 32]).is_err());
        let mut substituted = anchored.clone();
        substituted.state.execution.history_commitment[0] ^= 1;
        assert!(checked.evaluator_scope(&substituted,
            substituted.commitment().unwrap(), [14; 32]).is_err());
        assert_eq!(environment.projection, Some(Projection {
            prior_active_bond_inbox_root: [9; 32], prior_active_bond_inbox_count: 3,
            current_sidechain_height: 8 }));
        assert_eq!(environment.prior_active_root, Some([1; 32]));
        // Synthetic transcript verifier only: this tests context derivation,
        // never claims a cryptographic Alpha proof or a mined fixture.
        {
            use crate::conversion_parent_link_v3::tests::{parent_for_child_checkpoint, TranscriptVerifier};
            let parent = parent_for_child_checkpoint(&checkpoint.execution, [20; 32]);
            let mut full = environment.clone();
            full.current_bmm_parent = Some(Parent {
                block_hash_wire: parent.expected_parent_hash_internal,
                height: u64::from(parent.terminal_parent_predecessor.tip.height),
                median_time_past: u64::from(ecx_full_consensus_validator_v2::median_time_past_v2(
                    &parent.terminal_parent_predecessor.pow_context.previous_11_times).unwrap()),
            });
            let parent_binding = parent.binding.commitment().unwrap();
            let authenticate = |env: &EcxExecutionEnvironmentV1, root, cp_root| {
                CheckedAlphaExecutionContextV4::authenticate(env, root, [21; 32],
                    &checkpoint, cp_root, &header, &parent, parent_binding, &TranscriptVerifier::for_input(&parent))
            };
            let root = full.commitment().unwrap();
            let custody_authenticate = |env: &EcxExecutionEnvironmentV1, root, cp_root| {
                CheckedAlphaCustodyExecutionContextV4::authenticate(env, root, [21;32],
                    &custody_checkpoint, cp_root, &header, &parent, parent_binding, &TranscriptVerifier::for_input(&parent))
            };
            let custody_checked = custody_authenticate(&full, root, frozen_custody).unwrap();
            assert_eq!(custody_checked.environment(), &full);
            let custody_scope = custody_checked.evaluator_scope(frozen_custody, [14;32]).unwrap();
            assert_eq!(custody_scope.prior_child_checkpoint, frozen_custody);
            assert_eq!(custody_scope.ecx_environment, root);
            assert_eq!(custody_scope.parent_binding, parent_binding);
            assert!(custody_checked.evaluator_scope(frozen, [14;32]).is_err());
            assert!(custody_checked.evaluator_scope(frozen_custody, [0;32]).is_err());
            assert!(custody_authenticate(&full, [0;32], frozen_custody).is_err());
            assert!(custody_authenticate(&full, root, frozen).is_err());
            let checked = authenticate(&full, root, frozen).unwrap();
            assert_eq!(checked.context().ecx_environment, root);
            assert_eq!(checked.context().evaluator_binding, [21; 32]);
            assert_eq!(checked.checkpoint, checkpoint);
            assert_eq!(checked.environment, full);
            assert!(authenticate(&full, [0; 32], frozen).is_err());
            assert!(authenticate(&full, root, [22; 32]).is_err());
            for field in 0..7 {
                let mut wrong = full.clone();
                match field {
                    0 => wrong.current_bmm_parent.as_mut().unwrap().block_hash_wire[0] ^= 1,
                    1 => wrong.current_bmm_parent.as_mut().unwrap().height += 1,
                    2 => wrong.current_bmm_parent.as_mut().unwrap().median_time_past += 1,
                    3 => wrong.prior_active_root = Some([23; 32]),
                    4 => wrong.forced_processed_cursor += 1,
                    5 => wrong.projection.as_mut().unwrap().prior_active_bond_inbox_count += 1,
                    _ => wrong.projection.as_mut().unwrap().current_sidechain_height += 1,
                }
                // Even a matching claimed environment hash cannot replace
                // values derived from authenticated predecessor state.
                assert!(authenticate(&wrong, wrong.commitment().unwrap(), frozen).is_err(), "{field}");
                assert!(custody_authenticate(&wrong, wrong.commitment().unwrap(), frozen_custody).is_err(), "custody {field}");
            }
        }
        // ECX preparation uses the real authentication constructor. Parent
        // receipts remain exact synthetic transcripts, not SP1 evidence.
        {
            use crate::conversion_parent_link_v3::tests::{parent_for_child_checkpoint, TranscriptVerifier};
            use ecx_protocol_core::ecx_configuration_v1::EcxSuccessorBindingsV1;
            use ecx_proof_core::ecx_successor_state_v1::EcxSuccessorStateV1;
            let bindings = EcxSuccessorBindingsV1 {
                economic_configuration_hash: [11;32], oracle_configuration_hash: [12;32],
                matcher_configuration_hash: [13;32], funding_oracle_program_id: [14;32],
                account_execution_program_id: [15;32], vault_policy_hash: [16;32],
            };
            let base_parent = parent_for_child_checkpoint(&checkpoint.execution, [20;32]);
            let context_parent = Parent {
                block_hash_wire: base_parent.expected_parent_hash_internal,
                height: u64::from(base_parent.terminal_parent_predecessor.tip.height),
                median_time_past: u64::from(ecx_full_consensus_validator_v2::median_time_past_v2(
                    &base_parent.terminal_parent_predecessor.pow_context.previous_11_times).unwrap()),
            };
            let prior = EcxSuccessorStateV1 {
                bindings_hash: bindings.digest().unwrap(), accounts_root: [2;32],
                orders_root: [3;32], funding_root: [4;32], funding_index: -5,
                open_interest: 6, matcher_sequence: 7, matcher_receipt_hash: [8;32],
                sidechain_height: 7, parent_hash: context_parent.block_hash_wire,
                parent_height: context_parent.height, parent_mtp: context_parent.median_time_past,
                controlled_ecx_atoms: 100, vault_script_sha256: [9;32],
            };
            let authenticate_ecx_with_capital = |state: &EcxSuccessorStateV1, retain_capital: bool| {
                let mut h = header.clone(); h.exchange = state.digest().unwrap();
                let mut cp = checkpoint.clone();
                cp.execution.tip_internal = h.hash_internal().unwrap();
                cp.capital.as_mut().unwrap().exchange_state_root = h.exchange;
                if !retain_capital { cp.capital = None; }
                let frozen = cp.commitment().unwrap();
                let parent = parent_for_child_checkpoint(&cp.execution, [20;32]);
                let mut env = environment.clone();
                env.bind_checkpoint_projection(&cp, frozen, &h).unwrap();
                env.current_bmm_parent = Some(context_parent.clone());
                CheckedAlphaExecutionContextV4::authenticate(&env, env.commitment().unwrap(),
                    [21;32], &cp, frozen, &h, &parent, parent.binding.commitment().unwrap(),
                    &TranscriptVerifier::for_input(&parent)).unwrap()
            };
            let authenticate_ecx = |state: &EcxSuccessorStateV1|
                authenticate_ecx_with_capital(state, true);
            let checked = authenticate_ecx(&prior);
            let checkpoint_pin = Some(checked.checkpoint.commitment().unwrap());
            assert!(checked.check_match_execution_binding(Some(checked.context()), checkpoint_pin).is_ok());
            assert!(checked.check_match_execution_binding(None, checkpoint_pin).is_err());
            assert!(checked.check_match_execution_binding(Some(checked.context()), None).is_err());
            assert!(checked.check_match_execution_binding(Some(checked.context()), Some([99;32])).is_err());
            for field in 0..3 {
                let mut wrong = checked.context();
                match field {
                    0 => wrong.evaluator_binding[0] ^= 1,
                    1 => wrong.parent_statement[0] ^= 1,
                    _ => wrong.ecx_environment[0] ^= 1,
                }
                assert!(checked.check_match_execution_binding(Some(wrong), checkpoint_pin).is_err());
            }
            let next = checked.prepare_ecx_match_state(&prior, bindings).unwrap();
            let mut expected = prior.clone(); expected.sidechain_height = 8;
            assert_eq!(next, expected); // Every non-clock byte is preserved.
            let ecx_only = authenticate_ecx_with_capital(&prior, false);
            assert!(ecx_only.checkpoint.capital.is_none());
            assert!(ecx_only.environment.projection.is_none());
            assert_eq!(ecx_only.prepare_ecx_match_state(&prior, bindings).unwrap(), expected);
            assert!(ecx_only.prepare_ecx_match_state(&next, bindings).is_err());
            assert_ne!(next.digest().unwrap(), prior.digest().unwrap());
            assert!(checked.prepare_ecx_match_state(&next, bindings).is_err());
            let mut older = prior.clone();
            older.parent_height = context_parent.height.checked_sub(1).unwrap();
            older.parent_mtp = context_parent.median_time_past.checked_sub(1).unwrap();
            older.parent_hash = [98;32];
            assert_eq!(authenticate_ecx(&older).prepare_ecx_match_state(&older, bindings).unwrap(), expected);
            let mut wrong_bindings = bindings; wrong_bindings.vault_policy_hash = [99;32];
            assert!(checked.prepare_ecx_match_state(&prior, wrong_bindings).is_err());
            for field in 0..5 {
                let mut wrong = prior.clone();
                match field {
                    0 => wrong.sidechain_height = 8,
                    1 => wrong.parent_height += 1,
                    2 => wrong.parent_mtp += 1,
                    3 => wrong.parent_hash[0] ^= 1,
                    _ => wrong.parent_mtp = wrong.parent_mtp.saturating_sub(1),
                }
                assert!(authenticate_ecx(&wrong).prepare_ecx_match_state(&wrong, bindings).is_err(), "{field}");
            }
        }
        let unchanged = environment.clone();
        checkpoint.capital.as_mut().unwrap().node_inbox_root[0] ^= 1;
        assert!(environment.bind_checkpoint_projection(&checkpoint, frozen, &header).is_err());
        assert_eq!(environment, unchanged);
        let capital = checkpoint.capital.as_mut().unwrap();
        capital.proof_profile = 1;
        capital.node_inbox_count = u64::MAX as u128 + 1;
        let wide_commitment = checkpoint.commitment().unwrap();
        assert!(environment.bind_checkpoint_projection(&checkpoint, wide_commitment, &header).is_err());
        assert_eq!(environment, unchanged);
        checkpoint.capital = None;
        environment.bind_checkpoint_projection(&checkpoint, checkpoint.commitment().unwrap(), &header).unwrap();
        assert_eq!(environment.projection, None);
    }

    #[test]
    fn absent_environment_is_exact_and_rejects_hidden_bytes() {
        let value = EcxExecutionEnvironmentV1::default();
        let bytes = value.encode().unwrap();
        assert_eq!(bytes.len(), ENCODED_LENGTH);
        assert_eq!(EcxExecutionEnvironmentV1::decode(&bytes).unwrap(), value);
        for offset in 8..bytes.len() {
            // C permits independent processed cursors even with absent roots.
            if (107..123).contains(&offset) { continue; }
            let mut altered = bytes.clone(); altered[offset] = 2;
            assert!(EcxExecutionEnvironmentV1::decode(&altered).is_err(), "{offset}");
        }
        for length in 0..bytes.len() { assert!(EcxExecutionEnvironmentV1::decode(&bytes[..length]).is_err()); }
        let mut extra = bytes; extra.push(0);
        assert!(EcxExecutionEnvironmentV1::decode(&extra).is_err());
    }

    #[test]
    fn populated_environment_roundtrips_and_commits_each_field() {
        let value = EcxExecutionEnvironmentV1 {
            prior_active_root: Some([1; 32]), forced_inbox_root: Some([2; 32]),
            deposit_inbox_root: Some([3; 32]), forced_processed_cursor: 4, deposit_processed_cursor: 5,
            current_bmm_parent: Some(Parent { block_hash_wire: [6; 32], height: 7, median_time_past: 8 }),
            bond_identity: Some(BondIdentity {
                configuration_hash: [9; 32], asset_id: [10; 32], deployment_commitment: [11; 32],
                transition_cmr: [12; 32], collateral_vault_script_sha256: [13; 32], collateral_vault_cmr: [14; 32],
                insurance_reserve_script_sha256: [15; 32], insurance_reserve_cmr: [16; 32],
            }),
            incremental_identity: Some(IncrementalIdentity { activation_cmr: [17; 32], successor_transition_cmr: [18; 32] }),
            projection: Some(Projection { prior_active_bond_inbox_root: [19; 32], prior_active_bond_inbox_count: 20, current_sidechain_height: 21 }),
        };
        let bytes = value.encode().unwrap();
        assert_eq!(EcxExecutionEnvironmentV1::decode(&bytes).unwrap(), value);
        let original = value.commitment().unwrap();
        for offset in 8..bytes.len() {
            let mut changed = bytes.clone(); changed[offset] ^= 1;
            if let Ok(decoded) = EcxExecutionEnvironmentV1::decode(&changed) {
                assert_ne!(decoded.commitment().unwrap(), original, "{offset}");
            }
        }
    }

    #[test]
    fn native_presence_dependencies_are_enforced() {
        let mut value = EcxExecutionEnvironmentV1::default();
        value.incremental_identity = Some(IncrementalIdentity { activation_cmr: [1; 32], successor_transition_cmr: [2; 32] });
        assert!(value.validate().is_err());
        value.incremental_identity = None;
        value.current_bmm_parent = Some(Parent { block_hash_wire: [1; 32], height: 1, median_time_past: 0 });
        assert!(value.validate().is_err());
        value.current_bmm_parent.as_mut().unwrap().median_time_past = 1;
        let bytes = value.encode().unwrap();
        assert_eq!(EcxExecutionEnvironmentV1::decode(&bytes).unwrap(), value);
        let commitment = value.commitment().unwrap();
        value.forced_processed_cursor += 1;
        assert_ne!(value.commitment().unwrap(), commitment);
    }
}
