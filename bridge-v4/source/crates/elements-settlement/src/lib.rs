//! Elements confidential-output openings bound to node-derived deposit events.
//!
//! The Elements node authenticates transaction inclusion by appending each
//! recognized vault output to `DepositInboxStateV1`. This verifier then proves
//! that the exact committed output hides the configured USDD asset and credited
//! amount. No RPC response or relayer signature is trusted by this relation.

#![forbid(unsafe_code)]

pub mod finite_genesis;
pub mod explicit_creations;
pub mod public_deployment;
pub mod truthcoin_authority;

use ecx_protocol_core::{
    bond_inbox_redemption_staging_hidden_node_v2,
    bond_inbox_staging_source_authorization_commitment_v2,
    successor_bond_inbox_staging_source_authorization_commitment_v2,
    truthcoin_anchor_configuration_hash, usdd_checkpoint_authority_configuration_hash,
    verify_bond_inbox_entry_source_witness_v2, verify_successor_bond_inbox_entry_source_witness_v2,
    verify_truthcoin_anchor_successor, verify_usdd_checkpoint_successor, AnchorOutpointV1,
    BondInboxActionKindV2, BondInboxCustodyReceiptV2, BondInboxEntryV2,
    BondInboxRedemptionStagingRendererInputV2, DepositEventV1, DepositMarkerV1, DepositRequest,
    FrozenConfigurationV2, Hash32, ProtocolError, SignedWithdrawalRequest,
    SuccessorBondInboxEntryV2, SuccessorSignedWithdrawalRequestV2, TruthcoinAnchorDeploymentV1,
    TruthcoinAnchorStateV1, TruthcoinAnchorUpdateV1, TruthcoinAuthenticationConfigV1,
    UsddCheckpointConfigV1, UsddCheckpointUpdateV1, UsddEthereumCheckpointV1,
    MAX_BOND_INBOX_BUNDLE_BYTES_V2, MAX_BOND_INBOX_CUSTODY_RECEIPT_BYTES_V2,
    MAX_BOND_INBOX_SOURCE_TRANSACTION_BYTES_V2,
};
use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::hashes::{sha256, sha256d, Hash, HashEngine};
use elements::opcodes;
use elements::script::Instruction;
use elements::secp256k1_zkp::Secp256k1;
use elements::taproot::{LeafVersion, TapLeafHash, TapNodeHash};
use elements::{encode, AssetId, Transaction, TxOut};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const DEPOSIT_OPENING_VERSION: u8 = 1;
pub const MAX_ELEMENTS_TRANSACTION_BYTES: usize = 400_000;
pub const TRANSITION_SETTLEMENT_VERSION: u8 = 1;
pub const TRANSITION_SETTLEMENT_V2_VERSION: u8 = 2;
pub const BOND_SETTLEMENT_VERSION: u8 = 2;
pub const BOND_DEPLOYMENT_VERSION: u8 = 2;
pub const FROZEN_BOND_ASSET_VERSION: u8 = 2;
pub const BOND_DECIMALS_V2: u8 = 8;
pub const BOND_FIXED_SUPPLY_ATOMS_V2: u64 = 21_000_000 * 100_000_000;
pub const BOND_REISSUANCE_TOKEN_BURN_AMOUNT_V2: u64 = 1;
pub const TRUTHCOIN_ANCHOR_SETTLEMENT_VERSION: u8 = 1;
pub const USDD_CHECKPOINT_SETTLEMENT_VERSION: u8 = 1;
pub const CURSOR_MARKER_MAGIC: [u8; 4] = *b"ECXC";
pub const CURSOR_MARKER_VERSION: u8 = 1;
pub const WITHDRAWAL_BUNDLE_ENVELOPE_VERSION: u8 = 1;
pub const MAX_WITHDRAWAL_BUNDLE_BYTES: usize = 100_000;
/// Taproot-annex framing used by exactly one bond-inbox marker transaction.
/// The annex is removed before key-path script execution, so its bounded
/// encrypted bundle is not subject to the 520-byte executed-stack-element
/// limit. Its complete bytes remain committed by the source wtxid.
pub const BOND_INBOX_SOURCE_ANNEX_MAGIC_V2: [u8; 8] = *b"ECXBIN2\0";
pub const BOND_INBOX_SOURCE_ANNEX_VERSION_V2: u8 = 1;
pub const BOND_INBOX_SOURCE_KEYPATH_SIGNATURE_BYTES_V2: usize = 64;

/// Encode the one canonical source-annex payload. Receipt wrapper indices are
/// not duplicated on wire: the fixed V1 receipt byte at offset 73 carries its
/// one-based registry index, which must equal the wrapper's zero-based index
/// plus one.
pub fn bond_inbox_source_annex_v2(
    canonical_encrypted_bundle: &[u8],
    custody_receipts: &[BondInboxCustodyReceiptV2],
) -> Result<Vec<u8>, SettlementError> {
    if canonical_encrypted_bundle.is_empty()
        || canonical_encrypted_bundle.len() > MAX_BOND_INBOX_BUNDLE_BYTES_V2 as usize
        || !(3..=5).contains(&custody_receipts.len())
    {
        return Err(SettlementError::BondInboxSourceMismatch);
    }
    let bundle_len = u32::try_from(canonical_encrypted_bundle.len())
        .map_err(|_| SettlementError::BondInboxSourceMismatch)?;
    let mut annex = Vec::with_capacity(
        1 + BOND_INBOX_SOURCE_ANNEX_MAGIC_V2.len()
            + 1
            + 4
            + 1
            + canonical_encrypted_bundle.len()
            + custody_receipts.len() * (2 + MAX_BOND_INBOX_CUSTODY_RECEIPT_BYTES_V2),
    );
    annex.push(0x50);
    annex.extend_from_slice(&BOND_INBOX_SOURCE_ANNEX_MAGIC_V2);
    annex.push(BOND_INBOX_SOURCE_ANNEX_VERSION_V2);
    annex.extend_from_slice(&bundle_len.to_be_bytes());
    annex.push(
        u8::try_from(custody_receipts.len())
            .map_err(|_| SettlementError::BondInboxSourceMismatch)?,
    );
    annex.extend_from_slice(canonical_encrypted_bundle);
    let mut prior = None;
    for receipt in custody_receipts {
        let exact = receipt.exact_receipt_bytes.as_slice();
        if exact.len() != MAX_BOND_INBOX_CUSTODY_RECEIPT_BYTES_V2
            || exact[0] != 1
            || exact[73] != receipt.custodian_index.saturating_add(1)
            || prior.is_some_and(|value| receipt.custodian_index <= value)
            || usize::from(receipt.custodian_index) >= 5
        {
            return Err(SettlementError::BondInboxSourceMismatch);
        }
        prior = Some(receipt.custodian_index);
        annex.extend_from_slice(
            &u16::try_from(exact.len())
                .map_err(|_| SettlementError::BondInboxSourceMismatch)?
                .to_be_bytes(),
        );
        annex.extend_from_slice(exact);
    }
    Ok(annex)
}

/// Decode the source annex with exact length consumption. This deliberately
/// does not verify Ed25519 signatures; proof/node admission separately applies
/// the frozen V1 availability verifier to these exact round-tripped bytes.
pub fn decode_bond_inbox_source_annex_v2(
    annex: &[u8],
) -> Result<(Vec<u8>, Vec<BondInboxCustodyReceiptV2>), SettlementError> {
    const FIXED_PREFIX: usize = 1 + 8 + 1 + 4 + 1;
    if annex.len() < FIXED_PREFIX
        || annex[0] != 0x50
        || annex[1..9] != BOND_INBOX_SOURCE_ANNEX_MAGIC_V2
        || annex[9] != BOND_INBOX_SOURCE_ANNEX_VERSION_V2
    {
        return Err(SettlementError::BondInboxSourceMismatch);
    }
    let bundle_len = usize::try_from(u32::from_be_bytes(
        annex[10..14]
            .try_into()
            .map_err(|_| SettlementError::BondInboxSourceMismatch)?,
    ))
    .map_err(|_| SettlementError::BondInboxSourceMismatch)?;
    let receipt_count = usize::from(annex[14]);
    if bundle_len == 0
        || bundle_len > MAX_BOND_INBOX_BUNDLE_BYTES_V2 as usize
        || !(3..=5).contains(&receipt_count)
        || annex.len() < FIXED_PREFIX.saturating_add(bundle_len)
    {
        return Err(SettlementError::BondInboxSourceMismatch);
    }
    let bundle_end = FIXED_PREFIX + bundle_len;
    let bundle = annex[FIXED_PREFIX..bundle_end].to_vec();
    let mut cursor = bundle_end;
    let mut receipts = Vec::with_capacity(receipt_count);
    let mut prior = None;
    for _ in 0..receipt_count {
        if annex.len().saturating_sub(cursor) < 2 {
            return Err(SettlementError::BondInboxSourceMismatch);
        }
        let receipt_len = usize::from(u16::from_be_bytes(
            annex[cursor..cursor + 2]
                .try_into()
                .map_err(|_| SettlementError::BondInboxSourceMismatch)?,
        ));
        cursor += 2;
        if receipt_len != MAX_BOND_INBOX_CUSTODY_RECEIPT_BYTES_V2
            || annex.len().saturating_sub(cursor) < receipt_len
        {
            return Err(SettlementError::BondInboxSourceMismatch);
        }
        let exact_receipt_bytes = annex[cursor..cursor + receipt_len].to_vec();
        cursor += receipt_len;
        if exact_receipt_bytes[0] != 1 || !(1..=5).contains(&exact_receipt_bytes[73]) {
            return Err(SettlementError::BondInboxSourceMismatch);
        }
        let custodian_index = exact_receipt_bytes[73] - 1;
        if prior.is_some_and(|value| custodian_index <= value) {
            return Err(SettlementError::BondInboxSourceMismatch);
        }
        prior = Some(custodian_index);
        receipts.push(BondInboxCustodyReceiptV2 {
            custodian_index,
            exact_receipt_bytes,
        });
    }
    if cursor != annex.len() || bond_inbox_source_annex_v2(&bundle, &receipts)? != annex {
        return Err(SettlementError::BondInboxSourceMismatch);
    }
    Ok((bundle, receipts))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalBundleEnvelopeV1 {
    pub version: u8,
    pub checkpoint_height: u32,
    pub checkpoint_block_hash: Hash32,
    pub m6_no_witness: Vec<u8>,
}

impl WithdrawalBundleEnvelopeV1 {
    pub fn m6id(&self) -> Hash32 {
        sha256d::Hash::hash(&self.m6_no_witness).to_byte_array()
    }

    pub fn coinbase_script(&self) -> Result<Vec<u8>, SettlementError> {
        if self.version != WITHDRAWAL_BUNDLE_ENVELOPE_VERSION
            || self.m6_no_witness.is_empty()
            || self.m6_no_witness.len() > MAX_WITHDRAWAL_BUNDLE_BYTES
        {
            return Err(SettlementError::InvalidWithdrawalBundleEnvelope);
        }
        let length = u32::try_from(self.m6_no_witness.len())
            .map_err(|_| SettlementError::InvalidWithdrawalBundleEnvelope)?;
        let mut payload = b"ECXM".to_vec();
        payload.push(self.version);
        payload.extend_from_slice(&self.checkpoint_height.to_le_bytes());
        payload.extend_from_slice(&self.checkpoint_block_hash);
        payload.extend_from_slice(&length.to_le_bytes());
        payload.extend_from_slice(&self.m6_no_witness);
        let mut script = vec![opcodes::all::OP_RETURN.into_u8()];
        match payload.len() {
            0..=75 => script.push(payload.len() as u8),
            76..=255 => {
                script.push(opcodes::all::OP_PUSHDATA1.into_u8());
                script.push(payload.len() as u8);
            }
            256..=65_535 => {
                script.push(opcodes::all::OP_PUSHDATA2.into_u8());
                script.extend_from_slice(&(payload.len() as u16).to_le_bytes());
            }
            _ => {
                script.push(opcodes::all::OP_PUSHDATA4.into_u8());
                script.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            }
        }
        script.extend_from_slice(&payload);
        Ok(script)
    }

    pub fn verify_coinbase_script(
        &self,
        script: &[u8],
        expected_m6id: Hash32,
    ) -> Result<(), SettlementError> {
        if self.m6id() != expected_m6id || self.coinbase_script()? != script {
            return Err(SettlementError::InvalidWithdrawalBundleEnvelope);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialDepositOpeningV1 {
    pub version: u8,
    /// Exact full Elements transaction encoding, including output witnesses.
    pub transaction: Vec<u8>,
    pub amount: u64,
    pub asset_blinding_factor: [u8; 32],
    pub value_blinding_factor: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollateralInputOpeningV1 {
    pub input_index: u32,
    pub previous_transaction: Vec<u8>,
    pub previous_vout: u32,
    pub amount: u64,
    pub asset_blinding_factor: [u8; 32],
    pub value_blinding_factor: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CollateralOutputRoleV1 {
    VaultChange,
    Withdrawal { request_id: Hash32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollateralOutputOpeningV1 {
    pub output_index: u32,
    pub amount: u64,
    pub asset_blinding_factor: [u8; 32],
    pub value_blinding_factor: [u8; 32],
    pub role: CollateralOutputRoleV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionSettlementV1 {
    pub version: u8,
    /// Exact full transaction executed by the state and vault covenants.
    pub transaction: Vec<u8>,
    /// Every collateral input after the fixed singleton and fee-sponsor inputs.
    pub collateral_inputs: Vec<CollateralInputOpeningV1>,
    /// Every confidential output in the transaction.
    pub collateral_outputs: Vec<CollateralOutputOpeningV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedTransitionSettlementV1 {
    pub transition_txid: Hash32,
    pub forced_processed_cursor: u64,
    pub deposit_processed_cursor: u64,
    pub collateral_input_total: u64,
    pub collateral_output_total: u64,
    pub vault_change_total: u64,
    pub withdrawal_total: u64,
    pub settlement_root: Hash32,
}

/// Consensus-facing identity of the v2 first-loss bond. The issuance that
/// created `asset_id` is outside this verifier; every transaction accepted by
/// this settlement lane is post-deployment and therefore forbidden from
/// carrying either a fresh issuance or a reissuance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrozenBondAssetV2 {
    pub version: u8,
    pub asset_id: Hash32,
    pub inventory_vault_script_sha256: Hash32,
    pub redemption_queue_script_sha256: Hash32,
    pub reissuance_token_burn_script_sha256: Hash32,
}

impl FrozenBondAssetV2 {
    pub const VERSION: u8 = FROZEN_BOND_ASSET_VERSION;
    pub const DECIMALS: u8 = BOND_DECIMALS_V2;
    pub const FIXED_SUPPLY_ATOMS: u64 = BOND_FIXED_SUPPLY_ATOMS_V2;

    pub fn validate(&self) -> Result<(), SettlementError> {
        if self.version != Self::VERSION {
            return Err(SettlementError::UnsupportedVersion);
        }
        if self.asset_id == [0; 32]
            || self.inventory_vault_script_sha256 == [0; 32]
            || self.redemption_queue_script_sha256 == [0; 32]
            || self.reissuance_token_burn_script_sha256 == [0; 32]
            || self.inventory_vault_script_sha256 == self.redemption_queue_script_sha256
            || self.inventory_vault_script_sha256 == self.reissuance_token_burn_script_sha256
            || self.redemption_queue_script_sha256 == self.reissuance_token_burn_script_sha256
        {
            return Err(SettlementError::InvalidBondConfiguration);
        }
        Ok(())
    }
}

/// Exact initial issuance envelope that turns an Elements asset into the
/// frozen v2 ECX insurance bond. The only inflation key is forced into a
/// pinned, provably unspendable output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrozenBondDeploymentV2 {
    pub version: u8,
    pub transaction: Vec<u8>,
    pub issuance_input_index: u32,
    pub inventory_output_index: u32,
    pub inventory_asset_blinding_factor: [u8; 32],
    pub inventory_value_blinding_factor: [u8; 32],
    /// Opening of the confidential issuance pseudo-input. This generally
    /// differs from the inventory VBF because the inventory asset generator
    /// also carries a nonzero asset blinder.
    pub issuance_value_blinding_factor: [u8; 32],
    pub reissuance_token_burn_output_index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedFrozenBondDeploymentV2 {
    pub transaction_id: Hash32,
    pub issuance_previous_txid: Hash32,
    pub issuance_previous_vout: u32,
    pub bond_asset_id: Hash32,
    pub reissuance_token_asset_id: Hash32,
    pub inventory_output_index: u32,
    pub reissuance_token_burn_output_index: u32,
    pub fixed_supply_atoms: u64,
    pub deployment_commitment: Hash32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BondInputRoleV2 {
    /// Shares leaving the frozen inventory covenant for subscriptions.
    InventoryVault,
    /// Shares locked by the source bond-inbox transaction in its exact
    /// per-intent staging output.  This outpoint can be consumed by any valid
    /// transition producer; it is never a producer-selected holder input.
    StagedRedemptionEnqueue {
        /// Final FIFO request id for accepted actions, or zero for an exact
        /// rejected-action refund.
        redemption_id: Hash32,
        staging_intent_id: Hash32,
        claimant: Hash32,
        staging_script_sha256: Hash32,
        source_txid: Hash32,
        source_vout: u32,
    },
    /// Shares already locked in the FIFO redemption covenant.
    QueuedRedemption { redemption_id: Hash32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondInputOpeningV2 {
    pub input_index: u32,
    pub previous_transaction: Vec<u8>,
    pub previous_vout: u32,
    pub amount: u64,
    pub asset_blinding_factor: [u8; 32],
    pub value_blinding_factor: [u8; 32],
    pub role: BondInputRoleV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BondOutputRoleV2 {
    /// Unsubscribed inventory recreated under the frozen vault covenant.
    InventoryVaultChange,
    /// Newly subscribed shares delivered to the exact recipient covenant.
    Subscription {
        subscription_id: Hash32,
        recipient_script_sha256: Hash32,
    },
    /// Newly enqueued shares, bound to the request claimant and USDD destination.
    QueuedRedemptionEntry {
        redemption_id: Hash32,
        staging_intent_id: Hash32,
        claimant: Hash32,
        destination_script_sha256: Hash32,
    },
    /// The still-loss-bearing unexecuted portion of a queued redemption.
    QueuedRedemptionRemainder { redemption_id: Hash32 },
    /// Metadata-preserving remainder required by the unified v2 action gate.
    AuthenticatedQueuedRedemptionRemainder {
        redemption_id: Hash32,
        claimant: Hash32,
        destination_script_sha256: Hash32,
    },
    /// Executed redemption shares returned to fixed inventory.
    RedemptionInventoryReturn { redemption_id: Hash32 },
    /// A signed cancellation returns the complete unexecuted queue entry.
    CancelledRedemptionReturn {
        redemption_id: Hash32,
        claimant: Hash32,
        recipient_script_sha256: Hash32,
        /// Stable proof-verified cancellation identifier. It excludes the
        /// exact opening commitments so constructing this output cannot form
        /// a hash/signature fixed point.
        cancellation_id: Hash32,
    },
    /// A consumed enqueue that was deterministically rejected returns the
    /// complete staging amount to the signed delayed-refund destination.
    RejectedEnqueueRefund {
        staging_intent_id: Hash32,
        claimant: Hash32,
        recipient_script_sha256: Hash32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondOutputOpeningV2 {
    pub output_index: u32,
    pub amount: u64,
    pub asset_blinding_factor: [u8; 32],
    pub value_blinding_factor: [u8; 32],
    pub role: BondOutputRoleV2,
}

/// Dedicated post-deployment bond movement envelope. Every confidential
/// output in this transaction must appear in `bond_outputs`; explicit state,
/// sponsor-change, and policy-asset fee outputs may coexist. This lets the
/// verifier rule out an unclassified confidential output without weakening
/// the unchanged v1 collateral verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondSettlementV2 {
    pub version: u8,
    pub transaction: Vec<u8>,
    pub bond_inputs: Vec<BondInputOpeningV2>,
    pub bond_outputs: Vec<BondOutputOpeningV2>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedBondSettlementV2 {
    pub transaction_id: Hash32,
    pub bond_input_total: u64,
    pub bond_output_total: u64,
    pub inventory_input_total: u64,
    pub inventory_change_total: u64,
    pub subscription_total: u64,
    pub queued_redemption_input_total: u64,
    pub redemption_remainder_total: u64,
    pub redemption_inventory_return_total: u64,
    pub subscription_count: u32,
    pub redemption_count: u32,
    pub settlement_root: Hash32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CollateralInputRoleV2 {
    CollateralVault,
    InsuranceReserve,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollateralInputOpeningV2 {
    pub input_index: u32,
    pub previous_transaction: Vec<u8>,
    pub previous_vout: u32,
    pub amount: u64,
    pub asset_blinding_factor: [u8; 32],
    pub value_blinding_factor: [u8; 32],
    pub role: CollateralInputRoleV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CollateralOutputRoleV2 {
    CollateralVaultChange,
    InsuranceReserveChange,
    BondSubscriptionContribution {
        subscription_id: Hash32,
    },
    InsuranceRecapitalizationContribution {
        contribution_id: Hash32,
    },
    BondRedemptionPayment {
        redemption_id: Hash32,
        recipient_script_sha256: Hash32,
    },
    Withdrawal {
        request_id: Hash32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollateralOutputOpeningV2 {
    pub output_index: u32,
    pub amount: u64,
    pub asset_blinding_factor: [u8; 32],
    pub value_blinding_factor: [u8; 32],
    pub role: CollateralOutputRoleV2,
}

/// Atomic v2 exchange settlement. The exact transaction carries both USDD and
/// frozen-bond movements; all confidential inputs and outputs are classified
/// here so neither asset verifier mistakes the other asset for an escape hatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionSettlementV2 {
    pub version: u8,
    pub transaction: Vec<u8>,
    pub collateral_inputs: Vec<CollateralInputOpeningV2>,
    pub collateral_outputs: Vec<CollateralOutputOpeningV2>,
    pub bond_inputs: Vec<BondInputOpeningV2>,
    pub bond_outputs: Vec<BondOutputOpeningV2>,
}

/// Exact predecessor-output projection authenticated by a recursively proved
/// source transaction. Only V2 staged-redemption inputs may use this compact
/// form; vault, reserve, inventory and queue inputs continue to carry their
/// complete prior transition transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedPreviousOutputV2 {
    pub input_index: u32,
    pub previous_txid: Hash32,
    pub previous_vout: u32,
    pub exact_serialized_txout: Vec<u8>,
    pub exact_serialized_txout_witness: Vec<u8>,
}

/// Opening already verified by a recursively authenticated predecessor-
/// transaction child. This form is deliberately forbidden for staged inbox
/// outputs, whose source-authorization commitment still needs the exact
/// serialized TxOut inside this relation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedOpenedPreviousOutputV2 {
    pub input_index: u32,
    pub previous_txid: Hash32,
    pub previous_vout: u32,
    pub expected_asset_id: Hash32,
    pub amount: u64,
    pub script_sha256: Hash32,
    pub txout_sha256: Hash32,
    pub txout_witness_sha256: Hash32,
}

/// Private opening supplied to the independently recoverable predecessor
/// transaction child. The child verifies the exact confidential output once
/// and exposes only a fixed projection to its settlement-parent proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreviousTransactionOutputOpeningV2 {
    pub previous_vout: u32,
    pub expected_asset_id: Hash32,
    pub amount: u64,
    pub asset_blinding_factor: [u8; 32],
    pub value_blinding_factor: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedPreviousTransactionOutputV2 {
    pub previous_vout: u32,
    pub expected_asset_id: Hash32,
    pub amount: u64,
    pub script_sha256: Hash32,
    pub txout_sha256: Hash32,
    pub txout_witness_sha256: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPreviousTransactionV2 {
    pub txid: Hash32,
    pub wtxid: Hash32,
    pub transaction_len: u32,
    pub outputs: Vec<VerifiedPreviousTransactionOutputV2>,
}

/// Exact transition actions that the unified confidential transaction must
/// realize. Signature validity and FIFO state order are proved by the v2 guest;
/// their stable identifiers are bound here to the transaction. The transition
/// proof separately verifies the full signed cancellation and its exact
/// opening commitments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BondSettlementActionV2 {
    Subscription {
        subscription_id: Hash32,
        usdd_contribution_amount: u64,
        bond_share_amount: u64,
        recipient_script_sha256: Hash32,
    },
    InsuranceRecapitalizationContribution {
        contribution_id: Hash32,
        usdd_contribution_amount: u64,
    },
    EnqueueRedemption {
        redemption_id: Hash32,
        staging_intent_id: Hash32,
        claimant: Hash32,
        bond_share_amount: u64,
        staging_script_sha256: Hash32,
        source_txid: Hash32,
        source_vout: u32,
        source_authorization_commitment: Hash32,
        refund_script_sha256: Hash32,
        refund_not_before_parent_height: u64,
        destination_script_sha256: Hash32,
    },
    RefundRejectedEnqueue {
        staging_intent_id: Hash32,
        claimant: Hash32,
        bond_share_amount: u64,
        staging_script_sha256: Hash32,
        source_txid: Hash32,
        source_vout: u32,
        source_authorization_commitment: Hash32,
        refund_script_sha256: Hash32,
        refund_not_before_parent_height: u64,
    },
    CancelRedemption {
        redemption_id: Hash32,
        claimant: Hash32,
        bond_share_amount: u64,
        recipient_script_sha256: Hash32,
        cancellation_id: Hash32,
    },
    ExecuteRedemption {
        redemption_id: Hash32,
        claimant: Hash32,
        queued_share_amount: u64,
        redeemed_share_amount: u64,
        remainder_share_amount: u64,
        usdd_payment_amount: u64,
        destination_script_sha256: Hash32,
    },
}

impl BondSettlementActionV2 {
    pub fn action_id(&self) -> Hash32 {
        match *self {
            Self::Subscription {
                subscription_id, ..
            } => subscription_id,
            Self::InsuranceRecapitalizationContribution {
                contribution_id, ..
            } => contribution_id,
            Self::RefundRejectedEnqueue {
                staging_intent_id, ..
            } => staging_intent_id,
            Self::EnqueueRedemption { redemption_id, .. }
            | Self::CancelRedemption { redemption_id, .. }
            | Self::ExecuteRedemption { redemption_id, .. } => redemption_id,
        }
    }
}

/// Canonical ordered commitment to the complete action list consumed by the
/// unified settlement verifier. This is exported for recursive settlement
/// child public values; it is not a replacement for verifying every action.
pub fn bond_settlement_action_root_v2(actions: &[BondSettlementActionV2]) -> Hash32 {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(actions.len() as u32).to_be_bytes());
    for action in actions {
        match *action {
            BondSettlementActionV2::Subscription {
                subscription_id,
                usdd_contribution_amount,
                bond_share_amount,
                recipient_script_sha256,
            } => {
                bytes.push(0);
                bytes.extend_from_slice(&subscription_id);
                bytes.extend_from_slice(&usdd_contribution_amount.to_be_bytes());
                bytes.extend_from_slice(&bond_share_amount.to_be_bytes());
                bytes.extend_from_slice(&recipient_script_sha256);
            }
            BondSettlementActionV2::InsuranceRecapitalizationContribution {
                contribution_id,
                usdd_contribution_amount,
            } => {
                bytes.push(1);
                bytes.extend_from_slice(&contribution_id);
                bytes.extend_from_slice(&usdd_contribution_amount.to_be_bytes());
            }
            BondSettlementActionV2::EnqueueRedemption {
                redemption_id,
                staging_intent_id,
                claimant,
                bond_share_amount,
                staging_script_sha256,
                source_txid,
                source_vout,
                source_authorization_commitment,
                refund_script_sha256,
                refund_not_before_parent_height,
                destination_script_sha256,
            } => {
                bytes.push(2);
                for value in [
                    redemption_id,
                    staging_intent_id,
                    claimant,
                    staging_script_sha256,
                    source_txid,
                    source_authorization_commitment,
                    refund_script_sha256,
                    destination_script_sha256,
                ] {
                    bytes.extend_from_slice(&value);
                }
                bytes.extend_from_slice(&bond_share_amount.to_be_bytes());
                bytes.extend_from_slice(&source_vout.to_be_bytes());
                bytes.extend_from_slice(&refund_not_before_parent_height.to_be_bytes());
            }
            BondSettlementActionV2::RefundRejectedEnqueue {
                staging_intent_id,
                claimant,
                bond_share_amount,
                staging_script_sha256,
                source_txid,
                source_vout,
                source_authorization_commitment,
                refund_script_sha256,
                refund_not_before_parent_height,
            } => {
                bytes.push(3);
                for value in [
                    staging_intent_id,
                    claimant,
                    staging_script_sha256,
                    source_txid,
                    source_authorization_commitment,
                    refund_script_sha256,
                ] {
                    bytes.extend_from_slice(&value);
                }
                bytes.extend_from_slice(&bond_share_amount.to_be_bytes());
                bytes.extend_from_slice(&source_vout.to_be_bytes());
                bytes.extend_from_slice(&refund_not_before_parent_height.to_be_bytes());
            }
            BondSettlementActionV2::CancelRedemption {
                redemption_id,
                claimant,
                bond_share_amount,
                recipient_script_sha256,
                cancellation_id,
            } => {
                bytes.push(4);
                bytes.extend_from_slice(&redemption_id);
                bytes.extend_from_slice(&claimant);
                bytes.extend_from_slice(&bond_share_amount.to_be_bytes());
                bytes.extend_from_slice(&recipient_script_sha256);
                bytes.extend_from_slice(&cancellation_id);
            }
            BondSettlementActionV2::ExecuteRedemption {
                redemption_id,
                claimant,
                queued_share_amount,
                redeemed_share_amount,
                remainder_share_amount,
                usdd_payment_amount,
                destination_script_sha256,
            } => {
                bytes.push(5);
                bytes.extend_from_slice(&redemption_id);
                bytes.extend_from_slice(&claimant);
                for amount in [
                    queued_share_amount,
                    redeemed_share_amount,
                    remainder_share_amount,
                    usdd_payment_amount,
                ] {
                    bytes.extend_from_slice(&amount.to_be_bytes());
                }
                bytes.extend_from_slice(&destination_script_sha256);
            }
        }
    }
    sha256_tagged("ECX/bond-settlement-action-list/v1", &bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedTransitionSettlementV2 {
    pub transition_txid: Hash32,
    pub forced_processed_cursor: u64,
    pub deposit_processed_cursor: u64,
    pub collateral_input_total: u64,
    pub collateral_output_total: u64,
    pub collateral_vault_input_total: u64,
    pub insurance_reserve_input_total: u64,
    pub collateral_vault_change_total: u64,
    pub insurance_reserve_output_total: u64,
    pub subscription_contribution_total: u64,
    pub recapitalization_contribution_total: u64,
    pub redemption_payment_total: u64,
    pub withdrawal_total: u64,
    pub bond_input_total: u64,
    pub bond_output_total: u64,
    pub bond_inventory_input_total: u64,
    pub bond_inventory_change_total: u64,
    pub bond_subscription_total: u64,
    pub queued_redemption_input_total: u64,
    pub redemption_remainder_total: u64,
    pub redemption_inventory_return_total: u64,
    pub rejected_enqueue_refund_total: u64,
    pub collateral_settlement_root: Hash32,
    pub bond_settlement_root: Hash32,
    pub combined_settlement_root: Hash32,
}

/// Index-independent commitment classes used by signed V2 bond actions.
/// Final transaction input/output positions and previous-transaction bytes
/// are intentionally absent; the proof maps these logical allocations to the
/// exact opened transaction after a producer chooses its batch layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum LogicalAllocationKindV2 {
    SubscriptionInsuranceOutput = 0,
    SubscriptionBondOutput = 1,
    RecapitalizationInsuranceOutput = 2,
    EnqueueStagingBondInput = 3,
    EnqueueQueueBondOutput = 4,
    CancellationQueueBondInput = 5,
    CancellationBondReturnOutput = 6,
    ExecutionQueueBondInput = 7,
    ExecutionUsddPaymentOutput = 8,
    ExecutionInventoryBondOutput = 9,
    ExecutionQueueRemainderOutput = 10,
}

/// Commit one confidential economic allocation without binding a future
/// producer's transaction indices.  The exact transaction verifier still
/// authenticates the prior outpoint (for inputs), scriptPubKey and Pedersen
/// commitments; this digest is solely the stable signed intent layer.
#[allow(clippy::too_many_arguments)]
pub fn logical_allocation_commitment_v2(
    kind: LogicalAllocationKindV2,
    stable_id: Hash32,
    asset_id: Hash32,
    amount: u64,
    script_sha256: Hash32,
    asset_blinding_factor: [u8; 32],
    value_blinding_factor: [u8; 32],
) -> Result<Hash32, SettlementError> {
    if stable_id == [0; 32]
        || asset_id == [0; 32]
        || amount == 0
        || script_sha256 == [0; 32]
        || asset_blinding_factor == [0; 32]
        || value_blinding_factor == [0; 32]
        || asset_blinding_factor == value_blinding_factor
    {
        return Err(SettlementError::UnsafeBlindingFactorsV2);
    }
    let mut preimage = Vec::with_capacity(169);
    preimage.push(kind as u8);
    preimage.extend_from_slice(&stable_id);
    preimage.extend_from_slice(&asset_id);
    preimage.extend_from_slice(&amount.to_be_bytes());
    preimage.extend_from_slice(&script_sha256);
    preimage.extend_from_slice(&asset_blinding_factor);
    preimage.extend_from_slice(&value_blinding_factor);
    Ok(sha256_tagged(
        "ECX/logical-confidential-allocation/v2",
        &preimage,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedBondInboxSourceTransactionV2 {
    pub txid: Hash32,
    pub wtxid: Hash32,
    pub exact_witness_sha256: Hash32,
    pub staging_vout: Option<u32>,
    pub staging_txout_sha256: Option<Hash32>,
    pub staging_txout_witness_sha256: Option<Hash32>,
    pub staging_script_sha256: Option<Hash32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondInboxRedemptionStagingRenderV2 {
    pub process_leaf_hash: Hash32,
    pub refund_leaf_hash: Hash32,
    pub hidden_node_hash: Hash32,
    pub lower_branch_hash: Hash32,
    pub top_branch_hash: Hash32,
    pub script_pubkey: elements::Script,
}

fn tapbranch_elements_raw_bytes_v2(left: TapNodeHash, right: TapNodeHash) -> TapNodeHash {
    let mut engine = TapNodeHash::engine();
    // Elements consensus orders the serialized hash bytes. This matches this
    // Elements branch's `uint256::operator<` memcmp semantics; do not convert
    // through `arith_uint256` or another numeric representation.
    if left.as_byte_array() < right.as_byte_array() {
        engine.input(left.as_ref());
        engine.input(right.as_ref());
    } else {
        engine.input(right.as_ref());
        engine.input(left.as_ref());
    }
    TapNodeHash::from_engine(engine)
}

/// Render the exact V18 per-intent keyless Elements P2TR output.
///
/// Tree shape is fixed independently of TapBranch's hash sorting:
/// `Branch(process, Branch(refund, hidden_raw_node))`. Thus the process
/// control path contains `[lower]`, while refund contains `[hidden, process]`
/// and can verify the hidden term commitment at tappath index zero. The raw
/// hidden node is not a spendable TapLeaf. The key-path internal key is the
/// frozen BIP341 NUMS point, so no operator can bypass either script leaf.
pub fn bond_inbox_redemption_staging_render_v2(
    configuration: &FrozenConfigurationV2,
    input: BondInboxRedemptionStagingRendererInputV2,
) -> Result<BondInboxRedemptionStagingRenderV2, SettlementError> {
    configuration
        .validate()
        .map_err(SettlementError::Protocol)?;
    input.validate().map_err(SettlementError::Protocol)?;
    if input.chain_id != configuration.base.chain_id
        || input.configuration_hash != configuration.digest()
    {
        return Err(SettlementError::InvalidBondConfiguration);
    }
    let leaf_version =
        LeafVersion::from_u8(configuration.bond_inbox_redemption_staging_tapleaf_version)
            .map_err(|_| SettlementError::InvalidBondConfiguration)?;
    let process = elements::Script::from(
        configuration
            .bond_inbox_redemption_staging_process_cmr
            .to_vec(),
    );
    let refund = elements::Script::from(
        configuration
            .bond_inbox_redemption_staging_refund_cmr
            .to_vec(),
    );
    let process_hash = TapLeafHash::from_script(&process, leaf_version);
    let refund_hash = TapLeafHash::from_script(&refund, leaf_version);
    let process_node = TapNodeHash::from_byte_array(process_hash.to_byte_array());
    let refund_node = TapNodeHash::from_byte_array(refund_hash.to_byte_array());
    let hidden_hash = bond_inbox_redemption_staging_hidden_node_v2(
        configuration.bond_inbox_redemption_staging_renderer_domain,
        input,
    )?;
    let hidden_node = TapNodeHash::from_byte_array(hidden_hash);
    let lower_root = tapbranch_elements_raw_bytes_v2(refund_node, hidden_node);
    let top_root = tapbranch_elements_raw_bytes_v2(process_node, lower_root);
    let internal_key = elements::secp256k1_zkp::XOnlyPublicKey::from_slice(
        &configuration.bond_inbox_redemption_staging_internal_key,
    )
    .map_err(|_| SettlementError::InvalidBondConfiguration)?;
    let script = elements::Script::new_v1_p2tr(
        &Secp256k1::verification_only(),
        internal_key,
        Some(top_root),
    );
    let bytes = script.as_bytes();
    if bytes.len() != 34 || bytes[0] != opcodes::all::OP_PUSHNUM_1.into_u8() || bytes[1] != 32 {
        return Err(SettlementError::InvalidBondConfiguration);
    }
    Ok(BondInboxRedemptionStagingRenderV2 {
        process_leaf_hash: process_hash.to_byte_array(),
        refund_leaf_hash: refund_hash.to_byte_array(),
        hidden_node_hash: hidden_hash,
        lower_branch_hash: lower_root.to_byte_array(),
        top_branch_hash: top_root.to_byte_array(),
        script_pubkey: script,
    })
}

pub fn bond_inbox_redemption_staging_script_v2(
    configuration: &FrozenConfigurationV2,
    input: BondInboxRedemptionStagingRendererInputV2,
) -> Result<elements::Script, SettlementError> {
    Ok(bond_inbox_redemption_staging_render_v2(configuration, input)?.script_pubkey)
}

pub fn bond_inbox_redemption_staging_script_sha256_v2(
    configuration: &FrozenConfigurationV2,
    input: BondInboxRedemptionStagingRendererInputV2,
) -> Result<Hash32, SettlementError> {
    Ok(
        Sha256::digest(bond_inbox_redemption_staging_script_v2(configuration, input)?.as_bytes())
            .into(),
    )
}

/// The exact native Elements witness tail: input witnesses followed by output
/// witnesses, using their consensus encodings exactly as `Transaction`
/// serializes them after locktime when the witness flag is one.
pub fn elements_transaction_witness_bytes_v2(
    transaction_bytes: &[u8],
) -> Result<Vec<u8>, SettlementError> {
    let transaction = decode_bond_inbox_source_transaction_v2(transaction_bytes)?;
    if !transaction.has_witness() {
        return Err(SettlementError::BondInboxSourceMismatch);
    }
    let mut witness = Vec::new();
    for input in &transaction.input {
        witness.extend_from_slice(&encode::serialize(&input.witness));
    }
    for output in &transaction.output {
        witness.extend_from_slice(&encode::serialize(&output.witness));
    }
    if witness.is_empty() {
        return Err(SettlementError::BondInboxSourceMismatch);
    }
    Ok(witness)
}

/// Authenticate one bond-inbox source transaction against the node-derived
/// entry. Exactly one bond marker is permitted. Its bundle and receipts occupy
/// the designated input-zero Taproot key-path annex, never executed stack
/// elements. For enqueue, the exact confidential staging TxOut and signed
/// refund metadata are bound without a txid self-cycle.
pub fn verify_bond_inbox_source_transaction_v2(
    entry: &BondInboxEntryV2,
    source_transaction: &[u8],
    canonical_encrypted_bundle: &[u8],
    custody_receipts: &[BondInboxCustodyReceiptV2],
    configuration: &FrozenConfigurationV2,
) -> Result<VerifiedBondInboxSourceTransactionV2, SettlementError> {
    configuration.validate()?;
    if entry.marker.configuration_hash != configuration.digest() {
        return Err(SettlementError::BondInboxSourceMismatch);
    }
    let transaction = decode_bond_inbox_source_transaction_v2(source_transaction)?;
    let txid = transaction.txid().to_byte_array();
    let wtxid = transaction.wtxid().to_byte_array();
    if txid != entry.source_txid
        || wtxid != entry.source_wtxid
        || entry.source_transaction_len
            != u32::try_from(source_transaction.len())
                .map_err(|_| SettlementError::BondInboxSourceMismatch)?
        || canonical_encrypted_bundle.is_empty()
        || canonical_encrypted_bundle.len() > MAX_BOND_INBOX_BUNDLE_BYTES_V2 as usize
        || custody_receipts.len() < 3
        || custody_receipts.len() > 5
    {
        return Err(SettlementError::BondInboxSourceMismatch);
    }
    if transaction.input.is_empty()
        || transaction
            .input
            .iter()
            .any(|input| input.has_issuance() || input.is_pegin)
    {
        return Err(SettlementError::BondInboxSourceMismatch);
    }
    let witness = elements_transaction_witness_bytes_v2(source_transaction)?;
    verify_bond_inbox_entry_source_witness_v2(entry, &witness)?;

    let marker_output = transaction
        .output
        .get(
            usize::try_from(entry.marker_vout)
                .map_err(|_| SettlementError::BondInboxSourceMismatch)?,
        )
        .ok_or(SettlementError::BondInboxSourceMismatch)?;
    let policy_asset = AssetId::from_byte_array(configuration.base.policy_asset_id);
    if marker_output.asset != Asset::Explicit(policy_asset)
        || marker_output.value != Value::Explicit(0)
        || marker_output.nonce != Nonce::Null
        || !marker_output.witness.is_empty()
        || transaction
            .output
            .iter()
            .enumerate()
            .filter(|(_, output)| {
                output.script_pubkey.as_bytes().first() == Some(&opcodes::all::OP_RETURN.into_u8())
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>()
            != vec![usize::try_from(entry.marker_vout)
                .map_err(|_| SettlementError::BondInboxSourceMismatch)?]
    {
        return Err(SettlementError::BondInboxSourceMismatch);
    }
    let mut instructions = marker_output.script_pubkey.instructions_minimal();
    if instructions.next() != Some(Ok(Instruction::Op(opcodes::all::OP_RETURN)))
        || match instructions.next() {
            Some(Ok(Instruction::PushBytes(bytes))) => {
                bytes
                    != entry
                        .marker
                        .payload_bytes(MAX_BOND_INBOX_BUNDLE_BYTES_V2)?
                        .as_slice()
            }
            _ => true,
        }
        || instructions.next().is_some()
    {
        return Err(SettlementError::BondInboxSourceMismatch);
    }

    let designated = &transaction.input[0];
    if !designated.script_sig.is_empty()
        || designated.witness.amount_rangeproof.is_some()
        || designated.witness.inflation_keys_rangeproof.is_some()
        || !designated.witness.pegin_witness.is_empty()
        || designated.witness.script_witness.len() != 2
        || designated.witness.script_witness[0].len()
            != BOND_INBOX_SOURCE_KEYPATH_SIGNATURE_BYTES_V2
        || transaction.input.iter().skip(1).any(|input| {
            input
                .witness
                .script_witness
                .last()
                .is_some_and(|item| item.first() == Some(&0x50))
        })
    {
        return Err(SettlementError::BondInboxSourceMismatch);
    }
    let annex = &designated.witness.script_witness[1];
    let (decoded_bundle, decoded_receipts) = decode_bond_inbox_source_annex_v2(annex)?;
    if decoded_bundle != canonical_encrypted_bundle || decoded_receipts != custody_receipts {
        return Err(SettlementError::BondInboxSourceMismatch);
    }

    let (staging_vout, staging_txout_sha256, staging_txout_witness_sha256, staging_script_sha256) =
        if entry.marker.kind == BondInboxActionKindV2::RedemptionEnqueue {
            let staging_vout = entry.marker.staging_vout;
            let renderer_input = BondInboxRedemptionStagingRendererInputV2 {
                chain_id: entry.marker.chain_id,
                configuration_hash: entry.marker.configuration_hash,
                marker_signer: entry.marker.signer,
                stable_intent_id: entry.marker.staging_intent_id,
                staging_vout,
                refund_script_sha256: entry.marker.refund_script_sha256,
                refund_not_before_parent_height: entry.marker.refund_not_before_parent_height,
            };
            let staging = transaction
                .output
                .get(
                    usize::try_from(staging_vout)
                        .map_err(|_| SettlementError::BondInboxSourceMismatch)?,
                )
                .ok_or(SettlementError::BondInboxSourceMismatch)?;
            if !staging.asset.is_confidential()
                || !staging.value.is_confidential()
                || !staging.nonce.is_confidential()
                || staging.witness.surjection_proof.is_none()
                || staging.witness.rangeproof.is_none()
                || staging.script_pubkey.is_empty()
                || staging.script_pubkey
                    != bond_inbox_redemption_staging_script_v2(configuration, renderer_input)?
            {
                return Err(SettlementError::BondInboxSourceMismatch);
            }
            let serialized = encode::serialize(staging);
            let serialized_witness = encode::serialize(&staging.witness);
            if bond_inbox_staging_source_authorization_commitment_v2(
                &serialized,
                entry.marker.staging_intent_id,
                entry.marker.refund_script_sha256,
                entry.marker.refund_not_before_parent_height,
            )? != entry.marker.source_authorization_commitment
            {
                return Err(SettlementError::BondInboxSourceMismatch);
            }
            (
                Some(staging_vout),
                Some(Sha256::digest(&serialized).into()),
                Some(Sha256::digest(&serialized_witness).into()),
                Some(script_sha256(staging)),
            )
        } else {
            (None, None, None, None)
        };

    Ok(VerifiedBondInboxSourceTransactionV2 {
        txid,
        wtxid,
        exact_witness_sha256: Sha256::digest(&witness).into(),
        staging_vout,
        staging_txout_sha256,
        staging_txout_witness_sha256,
        staging_script_sha256,
    })
}

/// Authenticate a successor bond-inbox source transaction without narrowing
/// its node-assigned entry index. The transaction/annex policy is unchanged
/// from V18, while the marker and staging authorization use the successor
/// domains and canonical widths.
pub fn verify_successor_bond_inbox_source_transaction_v2(
    entry: &SuccessorBondInboxEntryV2,
    source_transaction: &[u8],
    canonical_encrypted_bundle: &[u8],
    custody_receipts: &[BondInboxCustodyReceiptV2],
    configuration: &FrozenConfigurationV2,
) -> Result<VerifiedBondInboxSourceTransactionV2, SettlementError> {
    configuration.validate()?;
    if entry.marker.configuration_hash != configuration.digest() {
        return Err(SettlementError::BondInboxSourceMismatch);
    }
    let transaction = decode_bond_inbox_source_transaction_v2(source_transaction)?;
    let txid = transaction.txid().to_byte_array();
    let wtxid = transaction.wtxid().to_byte_array();
    if txid != entry.source_txid
        || wtxid != entry.source_wtxid
        || entry.source_transaction_len
            != u32::try_from(source_transaction.len())
                .map_err(|_| SettlementError::BondInboxSourceMismatch)?
        || canonical_encrypted_bundle.is_empty()
        || canonical_encrypted_bundle.len() > MAX_BOND_INBOX_BUNDLE_BYTES_V2 as usize
        || custody_receipts.len() < 3
        || custody_receipts.len() > 5
    {
        return Err(SettlementError::BondInboxSourceMismatch);
    }
    if transaction.input.is_empty()
        || transaction
            .input
            .iter()
            .any(|input| input.has_issuance() || input.is_pegin)
    {
        return Err(SettlementError::BondInboxSourceMismatch);
    }
    let witness = elements_transaction_witness_bytes_v2(source_transaction)?;
    verify_successor_bond_inbox_entry_source_witness_v2(entry, &witness)?;

    let marker_output = transaction
        .output
        .get(
            usize::try_from(entry.marker_vout)
                .map_err(|_| SettlementError::BondInboxSourceMismatch)?,
        )
        .ok_or(SettlementError::BondInboxSourceMismatch)?;
    let policy_asset = AssetId::from_byte_array(configuration.base.policy_asset_id);
    if marker_output.asset != Asset::Explicit(policy_asset)
        || marker_output.value != Value::Explicit(0)
        || marker_output.nonce != Nonce::Null
        || !marker_output.witness.is_empty()
        || transaction
            .output
            .iter()
            .enumerate()
            .filter(|(_, output)| {
                output.script_pubkey.as_bytes().first() == Some(&opcodes::all::OP_RETURN.into_u8())
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>()
            != vec![usize::try_from(entry.marker_vout)
                .map_err(|_| SettlementError::BondInboxSourceMismatch)?]
    {
        return Err(SettlementError::BondInboxSourceMismatch);
    }
    let mut instructions = marker_output.script_pubkey.instructions_minimal();
    if instructions.next() != Some(Ok(Instruction::Op(opcodes::all::OP_RETURN)))
        || match instructions.next() {
            Some(Ok(Instruction::PushBytes(bytes))) => {
                bytes
                    != entry
                        .marker
                        .payload_bytes(MAX_BOND_INBOX_BUNDLE_BYTES_V2)?
                        .as_slice()
            }
            _ => true,
        }
        || instructions.next().is_some()
    {
        return Err(SettlementError::BondInboxSourceMismatch);
    }

    let designated = &transaction.input[0];
    if !designated.script_sig.is_empty()
        || designated.witness.amount_rangeproof.is_some()
        || designated.witness.inflation_keys_rangeproof.is_some()
        || !designated.witness.pegin_witness.is_empty()
        || designated.witness.script_witness.len() != 2
        || designated.witness.script_witness[0].len()
            != BOND_INBOX_SOURCE_KEYPATH_SIGNATURE_BYTES_V2
        || transaction.input.iter().skip(1).any(|input| {
            input
                .witness
                .script_witness
                .last()
                .is_some_and(|item| item.first() == Some(&0x50))
        })
    {
        return Err(SettlementError::BondInboxSourceMismatch);
    }
    let annex = &designated.witness.script_witness[1];
    let (decoded_bundle, decoded_receipts) = decode_bond_inbox_source_annex_v2(annex)?;
    if decoded_bundle != canonical_encrypted_bundle || decoded_receipts != custody_receipts {
        return Err(SettlementError::BondInboxSourceMismatch);
    }

    let (staging_vout, staging_txout_sha256, staging_txout_witness_sha256, staging_script_sha256) =
        if entry.marker.kind == BondInboxActionKindV2::RedemptionEnqueue {
            let staging_vout = entry.marker.staging_vout;
            let renderer_input = BondInboxRedemptionStagingRendererInputV2 {
                chain_id: entry.marker.chain_id,
                configuration_hash: entry.marker.configuration_hash,
                marker_signer: entry.marker.signer,
                stable_intent_id: entry.marker.staging_intent_id,
                staging_vout,
                refund_script_sha256: entry.marker.refund_script_sha256,
                refund_not_before_parent_height: entry.marker.refund_not_before_parent_height,
            };
            let staging = transaction
                .output
                .get(
                    usize::try_from(staging_vout)
                        .map_err(|_| SettlementError::BondInboxSourceMismatch)?,
                )
                .ok_or(SettlementError::BondInboxSourceMismatch)?;
            if !staging.asset.is_confidential()
                || !staging.value.is_confidential()
                || !staging.nonce.is_confidential()
                || staging.witness.surjection_proof.is_none()
                || staging.witness.rangeproof.is_none()
                || staging.script_pubkey.is_empty()
                || staging.script_pubkey
                    != bond_inbox_redemption_staging_script_v2(configuration, renderer_input)?
            {
                return Err(SettlementError::BondInboxSourceMismatch);
            }
            let serialized = encode::serialize(staging);
            let serialized_witness = encode::serialize(&staging.witness);
            if successor_bond_inbox_staging_source_authorization_commitment_v2(
                &serialized,
                entry.marker.staging_intent_id,
                entry.marker.refund_script_sha256,
                entry.marker.refund_not_before_parent_height,
            )? != entry.marker.source_authorization_commitment
            {
                return Err(SettlementError::BondInboxSourceMismatch);
            }
            (
                Some(staging_vout),
                Some(Sha256::digest(&serialized).into()),
                Some(Sha256::digest(&serialized_witness).into()),
                Some(script_sha256(staging)),
            )
        } else {
            (None, None, None, None)
        };

    Ok(VerifiedBondInboxSourceTransactionV2 {
        txid,
        wtxid,
        exact_witness_sha256: Sha256::digest(&witness).into(),
        staging_vout,
        staging_txout_sha256,
        staging_txout_witness_sha256,
        staging_script_sha256,
    })
}

/// Exact Elements transaction material for one rolling Truthcoin authority
/// update. The previous transactions are supplied as consensus witnesses so
/// the verifier never trusts caller-declared input assets or amounts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruthcoinAnchorSettlementV1 {
    pub version: u8,
    pub transaction: Vec<u8>,
    pub prior_authority_transaction: Vec<u8>,
    pub sponsor_previous_transaction: Vec<u8>,
    pub sponsor_previous_vout: u32,
}

/// Deployment-derived script bindings. A production Simplicity/Taproot
/// renderer must produce these hashes from the corresponding state
/// commitment; recording both makes accidental cross-state use fail closed at
/// this Rust boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruthcoinAnchorAuthorityScriptsV1 {
    pub prior_state_commitment: Hash32,
    pub prior_script_sha256: Hash32,
    pub successor_state_commitment: Hash32,
    pub successor_script_sha256: Hash32,
    pub sponsor_change_script_sha256: Hash32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedTruthcoinAnchorSettlementV1 {
    pub transaction_id: Hash32,
    pub prior_authority_outpoint: AnchorOutpointV1,
    pub successor_authority_outpoint: AnchorOutpointV1,
    pub sponsor_change_amount: u64,
    pub fee_amount: u64,
}

pub type UsddCheckpointSettlementV1 = TruthcoinAnchorSettlementV1;
pub type UsddCheckpointAuthorityScriptsV1 = TruthcoinAnchorAuthorityScriptsV1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedUsddCheckpointSettlementV1 {
    pub transaction_id: Hash32,
    pub prior_authority_outpoint: AnchorOutpointV1,
    pub successor_authority_outpoint: AnchorOutpointV1,
    pub sponsor_change_amount: u64,
    pub fee_amount: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SettlementError {
    #[error("unsupported settlement opening version")]
    UnsupportedVersion,
    #[error("malformed or non-canonical Elements transaction")]
    InvalidTransaction,
    #[error("deposit event does not authenticate this transaction output")]
    EventMismatch,
    #[error("deposit marker is missing, non-minimal, or mismatched")]
    MarkerMismatch,
    #[error("deposit output does not use the frozen collateral vault script")]
    WrongVaultScript,
    #[error("deposit output is not a valid confidential USDD commitment")]
    InvalidConfidentialOpening,
    #[error("transition settlement does not cover the exact vault inputs and outputs")]
    InvalidSettlementShape,
    #[error("v2 transition settlement does not classify the complete atomic transaction")]
    InvalidSettlementShapeV2,
    #[error("withdrawal request/output coverage is incomplete or duplicated")]
    WithdrawalMismatch,
    #[error("collateral input and output amounts do not conserve USDD")]
    CollateralConservation,
    #[error("frozen bond asset or covenant configuration is invalid")]
    InvalidBondConfiguration,
    #[error("frozen bond deployment issuance or output shape is invalid")]
    InvalidBondDeployment,
    #[error("bond reissuance token is not destroyed by the frozen unspendable output")]
    BondReissuanceTokenNotDestroyed,
    #[error("bond settlement has an invalid or incomplete transaction shape")]
    InvalidBondSettlementShape,
    #[error("issuance, reissuance, and peg-in inputs are forbidden in bond settlements")]
    BondIssuanceForbidden,
    #[error("bond commitment opening is invalid or uses a counterfeit asset")]
    InvalidBondOpening,
    #[error("v2 confidential openings use a zero or repeated blinding factor")]
    UnsafeBlindingFactorsV2,
    #[error("bond input or output does not use its frozen covenant script")]
    WrongBondScript,
    #[error("queued redemption input, remainder, and inventory return do not match")]
    BondRedemptionMismatch,
    #[error("bond inputs and outputs do not conserve the fixed supply")]
    BondConservation,
    #[error("atomic bond subscription or redemption legs are missing, duplicated, or mismatched")]
    BondActionMismatch,
    #[error(
        "bond inbox source transaction, native witness framing, or staging authorization mismatched"
    )]
    BondInboxSourceMismatch,
    #[error("Truthcoin anchor transaction does not have the frozen two-input/three-output shape")]
    InvalidTruthcoinAnchorShape,
    #[error("Truthcoin anchor authority asset, amount, or script is invalid")]
    InvalidTruthcoinAuthority,
    #[error("Truthcoin anchor fee sponsor does not conserve the Elements policy asset")]
    InvalidTruthcoinSponsor,
    #[error("Truthcoin anchor transaction linkage does not match the state update")]
    TruthcoinAnchorLinkage,
    #[error("USDD checkpoint authority transaction or state binding is invalid")]
    InvalidUsddCheckpointAuthority,
    #[error("USDD checkpoint transaction linkage does not match the state update")]
    UsddCheckpointLinkage,
    #[error("USDD checkpoint does not bind the authenticated inclusion-time BMM parent MTP")]
    UsddCheckpointContext,
    #[error("withdrawal bundle envelope is malformed or does not bind the M6ID")]
    InvalidWithdrawalBundleEnvelope,
    #[error("invalid protocol deposit: {0}")]
    Protocol(#[from] ProtocolError),
}

/// Verify the exact Elements spend-and-recreate envelope for the finalized
/// Ethereum checkpoint lane. It is deliberately separate from collateral and
/// Truthcoin state, despite sharing their strict authority transaction shape.
#[allow(clippy::too_many_arguments)]
pub fn verify_usdd_checkpoint_settlement(
    settlement: &UsddCheckpointSettlementV1,
    prior: &UsddEthereumCheckpointV1,
    successor: &UsddEthereumCheckpointV1,
    update: &UsddCheckpointUpdateV1,
    scripts: &UsddCheckpointAuthorityScriptsV1,
    config: &UsddCheckpointConfigV1,
    authority_asset_id: Hash32,
    authority_amount: u64,
    script_tree_configuration_hash: Hash32,
    policy_asset_id: Hash32,
    authenticated_parent_mtp: u64,
) -> Result<VerifiedUsddCheckpointSettlementV1, SettlementError> {
    if settlement.version != USDD_CHECKPOINT_SETTLEMENT_VERSION {
        return Err(SettlementError::UnsupportedVersion);
    }
    config.validate()?;
    update.validate()?;
    if authenticated_parent_mtp == 0 || successor.accepted_parent_mtp != authenticated_parent_mtp {
        return Err(SettlementError::UsddCheckpointContext);
    }
    if authority_asset_id == [0; 32]
        || authority_asset_id == policy_asset_id
        || authority_amount == 0
        || script_tree_configuration_hash == [0; 32]
        || config.authority_configuration_hash
            != usdd_checkpoint_authority_configuration_hash(
                authority_asset_id,
                authority_amount,
                script_tree_configuration_hash,
                policy_asset_id,
            )
        || scripts.prior_state_commitment != prior.commitment()
        || scripts.successor_state_commitment != successor.commitment()
        || scripts.prior_script_sha256 == [0; 32]
        || scripts.successor_script_sha256 == [0; 32]
        || scripts.sponsor_change_script_sha256 == [0; 32]
    {
        return Err(SettlementError::InvalidUsddCheckpointAuthority);
    }

    let transaction = decode_transaction(&settlement.transaction)?;
    let prior_transaction = decode_transaction(&settlement.prior_authority_transaction)?;
    let sponsor_transaction = decode_transaction(&settlement.sponsor_previous_transaction)?;
    if transaction.input.len() != 2
        || transaction.output.len() != 3
        || transaction
            .input
            .iter()
            .any(|input| input.has_issuance() || input.is_pegin())
    {
        return Err(SettlementError::InvalidTruthcoinAnchorShape);
    }

    let prior_vout = update.prior_authority_outpoint.vout;
    let prior_input = &transaction.input[0];
    if update.prior_authority_outpoint.txid != prior_transaction.txid().to_byte_array()
        || prior_input.previous_output.txid != prior_transaction.txid()
        || prior_input.previous_output.vout != prior_vout
    {
        return Err(SettlementError::UsddCheckpointLinkage);
    }
    let prior_output = prior_transaction
        .output
        .get(usize::try_from(prior_vout).map_err(|_| SettlementError::UsddCheckpointLinkage)?)
        .ok_or(SettlementError::UsddCheckpointLinkage)?;
    require_explicit_output(
        prior_output,
        authority_asset_id,
        authority_amount,
        scripts.prior_script_sha256,
    )
    .map_err(|_| SettlementError::InvalidUsddCheckpointAuthority)?;

    let sponsor_input = &transaction.input[1];
    if sponsor_input.previous_output.txid != sponsor_transaction.txid()
        || sponsor_input.previous_output.vout != settlement.sponsor_previous_vout
    {
        return Err(SettlementError::InvalidTruthcoinSponsor);
    }
    let sponsor_previous_output = sponsor_transaction
        .output
        .get(
            usize::try_from(settlement.sponsor_previous_vout)
                .map_err(|_| SettlementError::InvalidTruthcoinSponsor)?,
        )
        .ok_or(SettlementError::InvalidTruthcoinSponsor)?;
    let sponsor_input_amount = explicit_output_amount(sponsor_previous_output, policy_asset_id)
        .ok_or(SettlementError::InvalidTruthcoinSponsor)?;
    // Match the permissionless authority covenant's input/change equality.
    // A caller-selected descriptor alone cannot authorize a different recipient.
    if script_sha256(sponsor_previous_output) != scripts.sponsor_change_script_sha256 {
        return Err(SettlementError::InvalidTruthcoinSponsor);
    }

    require_explicit_output(
        &transaction.output[0],
        authority_asset_id,
        authority_amount,
        scripts.successor_script_sha256,
    )
    .map_err(|_| SettlementError::InvalidUsddCheckpointAuthority)?;
    let sponsor_change_amount = explicit_output_amount(&transaction.output[1], policy_asset_id)
        .filter(|_| {
            transaction.output[1].nonce == Nonce::Null
                && script_sha256(&transaction.output[1]) == scripts.sponsor_change_script_sha256
        })
        .ok_or(SettlementError::InvalidTruthcoinSponsor)?;
    let fee_output = &transaction.output[2];
    let fee_amount = explicit_output_amount(fee_output, policy_asset_id)
        .filter(|amount| *amount != 0)
        .filter(|_| fee_output.nonce == Nonce::Null && fee_output.script_pubkey.is_empty())
        .ok_or(SettlementError::InvalidTruthcoinSponsor)?;
    if sponsor_change_amount
        .checked_add(fee_amount)
        .filter(|total| *total == sponsor_input_amount)
        .is_none()
    {
        return Err(SettlementError::InvalidTruthcoinSponsor);
    }

    let transaction_id = transaction.txid().to_byte_array();
    if update.successor_transaction_id != transaction_id
        || update.successor_authority_output_index != 0
    {
        return Err(SettlementError::UsddCheckpointLinkage);
    }
    verify_usdd_checkpoint_successor(config, prior, successor)?;

    Ok(VerifiedUsddCheckpointSettlementV1 {
        transaction_id,
        prior_authority_outpoint: update.prior_authority_outpoint,
        successor_authority_outpoint: AnchorOutpointV1 {
            txid: transaction_id,
            vout: 0,
        },
        sponsor_change_amount,
        fee_amount,
    })
}

/// Verify the complete public transaction envelope around a proved Truthcoin
/// state transition. Input/output positions are deliberately exact: this lane
/// never carries ECX collateral, orders, issuance, peg-ins, or extra outputs.
#[allow(clippy::too_many_arguments)]
pub fn verify_truthcoin_anchor_settlement(
    settlement: &TruthcoinAnchorSettlementV1,
    prior: &TruthcoinAnchorStateV1,
    successor: &TruthcoinAnchorStateV1,
    update: &TruthcoinAnchorUpdateV1,
    scripts: &TruthcoinAnchorAuthorityScriptsV1,
    authentication: &TruthcoinAuthenticationConfigV1,
    deployment: &TruthcoinAnchorDeploymentV1,
    policy_asset_id: Hash32,
) -> Result<VerifiedTruthcoinAnchorSettlementV1, SettlementError> {
    if settlement.version != TRUTHCOIN_ANCHOR_SETTLEMENT_VERSION {
        return Err(SettlementError::UnsupportedVersion);
    }
    authentication.validate()?;
    deployment.validate(policy_asset_id)?;
    let expected_configuration_hash =
        truthcoin_anchor_configuration_hash(authentication, deployment, policy_asset_id);
    if prior.configuration_hash != expected_configuration_hash
        || successor.configuration_hash != expected_configuration_hash
        || scripts.prior_script_sha256 == [0; 32]
        || scripts.successor_script_sha256 == [0; 32]
        || scripts.sponsor_change_script_sha256 == [0; 32]
        || scripts.prior_state_commitment != prior.commitment()
        || scripts.successor_state_commitment != successor.commitment()
    {
        return Err(SettlementError::InvalidTruthcoinAuthority);
    }

    let transaction = decode_transaction(&settlement.transaction)?;
    let prior_transaction = decode_transaction(&settlement.prior_authority_transaction)?;
    let sponsor_transaction = decode_transaction(&settlement.sponsor_previous_transaction)?;
    if transaction.input.len() != 2
        || transaction.output.len() != 3
        || transaction
            .input
            .iter()
            .any(|input| input.has_issuance() || input.is_pegin())
    {
        return Err(SettlementError::InvalidTruthcoinAnchorShape);
    }

    let prior_vout = update.prior_authority_outpoint.vout;
    let prior_input = &transaction.input[0];
    if update.prior_authority_outpoint.txid != prior_transaction.txid().to_byte_array()
        || prior_input.previous_output.txid != prior_transaction.txid()
        || prior_input.previous_output.vout != prior_vout
    {
        return Err(SettlementError::TruthcoinAnchorLinkage);
    }
    let prior_output = prior_transaction
        .output
        .get(usize::try_from(prior_vout).map_err(|_| SettlementError::TruthcoinAnchorLinkage)?)
        .ok_or(SettlementError::TruthcoinAnchorLinkage)?;
    require_explicit_output(
        prior_output,
        deployment.authority_asset_id,
        deployment.authority_amount,
        scripts.prior_script_sha256,
    )
    .map_err(|_| SettlementError::InvalidTruthcoinAuthority)?;

    let sponsor_input = &transaction.input[1];
    if sponsor_input.previous_output.txid != sponsor_transaction.txid()
        || sponsor_input.previous_output.vout != settlement.sponsor_previous_vout
    {
        return Err(SettlementError::InvalidTruthcoinSponsor);
    }
    let sponsor_previous_output = sponsor_transaction
        .output
        .get(
            usize::try_from(settlement.sponsor_previous_vout)
                .map_err(|_| SettlementError::InvalidTruthcoinSponsor)?,
        )
        .ok_or(SettlementError::InvalidTruthcoinSponsor)?;
    let sponsor_input_amount = explicit_output_amount(sponsor_previous_output, policy_asset_id)
        .ok_or(SettlementError::InvalidTruthcoinSponsor)?;

    require_explicit_output(
        &transaction.output[0],
        deployment.authority_asset_id,
        deployment.authority_amount,
        scripts.successor_script_sha256,
    )
    .map_err(|_| SettlementError::InvalidTruthcoinAuthority)?;
    // Match the keyless authority leaf: change returns to the sponsor input.
    if sponsor_previous_output.nonce != Nonce::Null
        || script_sha256(sponsor_previous_output) != scripts.sponsor_change_script_sha256
    {
        return Err(SettlementError::InvalidTruthcoinSponsor);
    }
    let sponsor_change_amount = explicit_output_amount(&transaction.output[1], policy_asset_id)
        .filter(|_| {
            transaction.output[1].nonce == Nonce::Null
                && script_sha256(&transaction.output[1]) == scripts.sponsor_change_script_sha256
        })
        .ok_or(SettlementError::InvalidTruthcoinSponsor)?;
    let fee_output = &transaction.output[2];
    let fee_amount = explicit_output_amount(fee_output, policy_asset_id)
        .filter(|amount| *amount != 0)
        .filter(|_| fee_output.nonce == Nonce::Null && fee_output.script_pubkey.is_empty())
        .ok_or(SettlementError::InvalidTruthcoinSponsor)?;
    if sponsor_change_amount
        .checked_add(fee_amount)
        .filter(|total| *total == sponsor_input_amount)
        .is_none()
    {
        return Err(SettlementError::InvalidTruthcoinSponsor);
    }

    let transaction_id = transaction.txid().to_byte_array();
    if update.successor_transaction_id != transaction_id
        || update.successor_authority_output_index != 0
    {
        return Err(SettlementError::TruthcoinAnchorLinkage);
    }
    verify_truthcoin_anchor_successor(prior, successor, update)?;

    Ok(VerifiedTruthcoinAnchorSettlementV1 {
        transaction_id,
        prior_authority_outpoint: update.prior_authority_outpoint,
        successor_authority_outpoint: AnchorOutpointV1 {
            txid: transaction_id,
            vout: 0,
        },
        sponsor_change_amount,
        fee_amount,
    })
}

/// Verify the collateral side of the exact state-transition transaction.
/// Inputs 0 and 1 are reserved for the state singleton and explicit fee
/// sponsor. Every later input must spend a proven confidential vault output;
/// every confidential output must be opened as either vault change or one
/// exact signed withdrawal.
fn transition_processed_cursors(transaction: &Transaction) -> Result<(u64, u64), SettlementError> {
    let mut decoded = None;
    for output in &transaction.output {
        let mut instructions = output.script_pubkey.instructions_minimal();
        if instructions.next() != Some(Ok(Instruction::Op(opcodes::all::OP_RETURN))) {
            continue;
        }
        let payload = match instructions.next() {
            Some(Ok(Instruction::PushBytes(bytes))) => bytes,
            _ => continue,
        };
        if payload.len() < CURSOR_MARKER_MAGIC.len()
            || payload[..CURSOR_MARKER_MAGIC.len()] != CURSOR_MARKER_MAGIC
        {
            continue;
        }
        if instructions.next().is_some()
            || payload.len() != 21
            || payload[4] != CURSOR_MARKER_VERSION
            || decoded.is_some()
        {
            return Err(SettlementError::MarkerMismatch);
        }
        let forced = u64::from_le_bytes(
            payload[5..13]
                .try_into()
                .map_err(|_| SettlementError::MarkerMismatch)?,
        );
        let deposit = u64::from_le_bytes(
            payload[13..21]
                .try_into()
                .map_err(|_| SettlementError::MarkerMismatch)?,
        );
        decoded = Some((forced, deposit));
    }
    decoded.ok_or(SettlementError::MarkerMismatch)
}

pub fn verify_transition_settlement(
    settlement: &TransitionSettlementV1,
    withdrawals: &[SignedWithdrawalRequest],
    expected_usdd_asset_id: Hash32,
    expected_vault_script_sha256: Hash32,
) -> Result<VerifiedTransitionSettlementV1, SettlementError> {
    use std::collections::{BTreeMap, BTreeSet};

    if settlement.version != TRANSITION_SETTLEMENT_VERSION {
        return Err(SettlementError::UnsupportedVersion);
    }
    let transaction = decode_transaction(&settlement.transaction)?;
    let (forced_processed_cursor, deposit_processed_cursor) =
        transition_processed_cursors(&transaction)?;
    if transaction.input.len() < 2 || transaction.output.len() < 3 {
        return Err(SettlementError::InvalidSettlementShape);
    }
    // Issuance and peg-in value creation are never valid inside an exchange
    // state transition. This covers the proof-managed collateral inputs after
    // the two fixed inputs as well as the singleton and sponsor positions.
    if transaction
        .input
        .iter()
        .any(|input| input.has_issuance() || input.is_pegin())
    {
        return Err(SettlementError::InvalidSettlementShape);
    }

    let mut inputs = BTreeMap::new();
    let mut input_total = 0u64;
    for opening in &settlement.collateral_inputs {
        let index = usize::try_from(opening.input_index)
            .map_err(|_| SettlementError::InvalidSettlementShape)?;
        if index < 2 || inputs.insert(index, ()).is_some() {
            return Err(SettlementError::InvalidSettlementShape);
        }
        let transaction_input = transaction
            .input
            .get(index)
            .ok_or(SettlementError::InvalidSettlementShape)?;
        let previous = decode_transaction(&opening.previous_transaction)?;
        if transaction_input.previous_output.txid != previous.txid()
            || transaction_input.previous_output.vout != opening.previous_vout
        {
            return Err(SettlementError::InvalidSettlementShape);
        }
        let previous_output = previous
            .output
            .get(
                usize::try_from(opening.previous_vout)
                    .map_err(|_| SettlementError::InvalidSettlementShape)?,
            )
            .ok_or(SettlementError::InvalidSettlementShape)?;
        if script_sha256(previous_output) != expected_vault_script_sha256 {
            return Err(SettlementError::WrongVaultScript);
        }
        verify_output_commitment(
            previous_output,
            opening.amount,
            opening.asset_blinding_factor,
            opening.value_blinding_factor,
            expected_usdd_asset_id,
        )?;
        input_total = input_total
            .checked_add(opening.amount)
            .ok_or(SettlementError::CollateralConservation)?;
    }
    if inputs.len() != transaction.input.len().saturating_sub(2)
        || !(2..transaction.input.len()).all(|index| inputs.contains_key(&index))
    {
        return Err(SettlementError::InvalidSettlementShape);
    }

    let expected_withdrawals: BTreeMap<Hash32, &SignedWithdrawalRequest> = withdrawals
        .iter()
        .map(|request| (request.request.request_id(), request))
        .collect();
    if expected_withdrawals.len() != withdrawals.len() {
        return Err(SettlementError::WithdrawalMismatch);
    }
    let mut covered_withdrawals = BTreeSet::new();
    let mut output_indices = BTreeSet::new();
    let mut output_total = 0u64;
    let mut vault_change_total = 0u64;
    let mut withdrawal_total = 0u64;
    let mut settlement_commitments = Vec::new();
    for opening in &settlement.collateral_outputs {
        let index = usize::try_from(opening.output_index)
            .map_err(|_| SettlementError::InvalidSettlementShape)?;
        if !output_indices.insert(index) {
            return Err(SettlementError::InvalidSettlementShape);
        }
        let output = transaction
            .output
            .get(index)
            .ok_or(SettlementError::InvalidSettlementShape)?;
        verify_output_commitment(
            output,
            opening.amount,
            opening.asset_blinding_factor,
            opening.value_blinding_factor,
            expected_usdd_asset_id,
        )?;
        let role_hash = match opening.role {
            CollateralOutputRoleV1::VaultChange => {
                if script_sha256(output) != expected_vault_script_sha256 {
                    return Err(SettlementError::WrongVaultScript);
                }
                vault_change_total = vault_change_total
                    .checked_add(opening.amount)
                    .ok_or(SettlementError::CollateralConservation)?;
                sha256_tagged(
                    "ECX/settlement-vault-change/v1",
                    &opening.output_index.to_be_bytes(),
                )
            }
            CollateralOutputRoleV1::Withdrawal { request_id } => {
                let request = expected_withdrawals
                    .get(&request_id)
                    .ok_or(SettlementError::WithdrawalMismatch)?;
                if !covered_withdrawals.insert(request_id)
                    || request.request.amount != opening.amount
                    || script_sha256(output) != request.request.destination_script_hash
                {
                    return Err(SettlementError::WithdrawalMismatch);
                }
                withdrawal_total = withdrawal_total
                    .checked_add(opening.amount)
                    .ok_or(SettlementError::CollateralConservation)?;
                request_id
            }
        };
        output_total = output_total
            .checked_add(opening.amount)
            .ok_or(SettlementError::CollateralConservation)?;
        let mut commitment = Vec::with_capacity(44);
        commitment.extend_from_slice(&opening.output_index.to_be_bytes());
        commitment.extend_from_slice(&opening.amount.to_be_bytes());
        commitment.extend_from_slice(&role_hash);
        settlement_commitments.push(sha256_tagged("ECX/settlement-output/v1", &commitment));
    }
    if covered_withdrawals.len() != expected_withdrawals.len() {
        return Err(SettlementError::WithdrawalMismatch);
    }

    // A dedicated state transition may contain no unaccounted confidential
    // output. Explicit state-authority, sponsor-change, and fee outputs remain
    // outside this confidential collateral set.
    for (index, output) in transaction.output.iter().enumerate() {
        let confidential = output.asset.is_confidential()
            || output.value.is_confidential()
            || output.nonce.is_confidential();
        if confidential != output_indices.contains(&index) {
            return Err(SettlementError::InvalidSettlementShape);
        }
        if output
            .asset
            .explicit()
            .is_some_and(|asset| asset.into_inner().to_byte_array() == expected_usdd_asset_id)
        {
            return Err(SettlementError::InvalidSettlementShape);
        }
    }
    if input_total != output_total
        || withdrawal_total
            != withdrawals
                .iter()
                .try_fold(0u64, |sum, request| sum.checked_add(request.request.amount))
                .ok_or(SettlementError::CollateralConservation)?
    {
        return Err(SettlementError::CollateralConservation);
    }
    settlement_commitments.sort_unstable();
    let settlement_root = sha256_tagged(
        "ECX/collateral-settlement/v1",
        &settlement_commitments.concat(),
    );
    Ok(VerifiedTransitionSettlementV1 {
        transition_txid: transaction.txid().to_byte_array(),
        forced_processed_cursor,
        deposit_processed_cursor,
        collateral_input_total: input_total,
        collateral_output_total: output_total,
        vault_change_total,
        withdrawal_total,
        settlement_root,
    })
}

/// Verify one atomic v2 transaction containing both confidential USDD and the
/// frozen insurance-bond asset. Subscription and executed-redemption IDs must
/// occur exactly once on both asset legs. Queue maturity/FIFO eligibility and
/// economic share/NAV arithmetic are proved by the txid-bound v2 transition;
/// this boundary authenticates its exact Elements conservation envelope.
#[allow(clippy::too_many_arguments)]
pub fn verify_transition_settlement_v2(
    settlement: &TransitionSettlementV2,
    withdrawals: &[SignedWithdrawalRequest],
    bond_actions: &[BondSettlementActionV2],
    expected_usdd_asset_id: Hash32,
    expected_collateral_vault_script_sha256: Hash32,
    expected_insurance_reserve_script_sha256: Hash32,
    frozen_bond_asset: &FrozenBondAssetV2,
) -> Result<VerifiedTransitionSettlementV2, SettlementError> {
    verify_transition_settlement_v2_with_authenticated_previous_outputs(
        settlement,
        withdrawals,
        bond_actions,
        expected_usdd_asset_id,
        expected_collateral_vault_script_sha256,
        expected_insurance_reserve_script_sha256,
        frozen_bond_asset,
        &[],
    )
}

/// Verify selected confidential outputs from one exact predecessor
/// transaction. Output requests must be strictly vout-ordered so the public
/// projection has one canonical encoding and cannot duplicate an opening.
pub fn verify_previous_transaction_output_openings_v2(
    previous_transaction: &[u8],
    openings: &[PreviousTransactionOutputOpeningV2],
) -> Result<VerifiedPreviousTransactionV2, SettlementError> {
    if previous_transaction.is_empty()
        || previous_transaction.len() > MAX_ELEMENTS_TRANSACTION_BYTES
        || openings.is_empty()
    {
        return Err(SettlementError::InvalidSettlementShapeV2);
    }
    let transaction = decode_transaction(previous_transaction)?;
    let mut previous_vout = None;
    let mut outputs = Vec::with_capacity(openings.len());
    for opening in openings {
        if opening.expected_asset_id == [0; 32]
            || opening.amount == 0
            || previous_vout.is_some_and(|prior| prior >= opening.previous_vout)
        {
            return Err(SettlementError::InvalidSettlementShapeV2);
        }
        previous_vout = Some(opening.previous_vout);
        let output = transaction
            .output
            .get(
                usize::try_from(opening.previous_vout)
                    .map_err(|_| SettlementError::InvalidSettlementShapeV2)?,
            )
            .ok_or(SettlementError::InvalidSettlementShapeV2)?;
        verify_output_commitment(
            output,
            opening.amount,
            opening.asset_blinding_factor,
            opening.value_blinding_factor,
            opening.expected_asset_id,
        )?;
        outputs.push(VerifiedPreviousTransactionOutputV2 {
            previous_vout: opening.previous_vout,
            expected_asset_id: opening.expected_asset_id,
            amount: opening.amount,
            script_sha256: script_sha256(output),
            txout_sha256: Sha256::digest(encode::serialize(output)).into(),
            txout_witness_sha256: Sha256::digest(encode::serialize(&output.witness)).into(),
        });
    }
    Ok(VerifiedPreviousTransactionV2 {
        txid: transaction.txid().to_byte_array(),
        wtxid: transaction.wtxid().to_byte_array(),
        transaction_len: u32::try_from(previous_transaction.len())
            .map_err(|_| SettlementError::InvalidSettlementShapeV2)?,
        outputs,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn verify_transition_settlement_v2_with_authenticated_previous_outputs(
    settlement: &TransitionSettlementV2,
    withdrawals: &[SignedWithdrawalRequest],
    bond_actions: &[BondSettlementActionV2],
    expected_usdd_asset_id: Hash32,
    expected_collateral_vault_script_sha256: Hash32,
    expected_insurance_reserve_script_sha256: Hash32,
    frozen_bond_asset: &FrozenBondAssetV2,
    authenticated_previous_outputs: &[AuthenticatedPreviousOutputV2],
) -> Result<VerifiedTransitionSettlementV2, SettlementError> {
    verify_transition_settlement_v2_with_authenticated_opened_previous_outputs(
        settlement,
        withdrawals,
        bond_actions,
        expected_usdd_asset_id,
        expected_collateral_vault_script_sha256,
        expected_insurance_reserve_script_sha256,
        frozen_bond_asset,
        authenticated_previous_outputs,
        &[],
    )
}

#[allow(clippy::too_many_arguments)]
pub fn verify_transition_settlement_v2_with_authenticated_opened_previous_outputs(
    settlement: &TransitionSettlementV2,
    withdrawals: &[SignedWithdrawalRequest],
    bond_actions: &[BondSettlementActionV2],
    expected_usdd_asset_id: Hash32,
    expected_collateral_vault_script_sha256: Hash32,
    expected_insurance_reserve_script_sha256: Hash32,
    frozen_bond_asset: &FrozenBondAssetV2,
    authenticated_previous_outputs: &[AuthenticatedPreviousOutputV2],
    authenticated_opened_previous_outputs: &[AuthenticatedOpenedPreviousOutputV2],
) -> Result<VerifiedTransitionSettlementV2, SettlementError> {
    let expected_withdrawals: Vec<ExpectedWithdrawalV2> = withdrawals
        .iter()
        .map(|request| ExpectedWithdrawalV2 {
            request_id: request.request.request_id(),
            amount: request.request.amount,
            destination_script_hash: request.request.destination_script_hash,
        })
        .collect();
    verify_transition_settlement_v2_with_expected_withdrawals(
        settlement,
        &expected_withdrawals,
        bond_actions,
        expected_usdd_asset_id,
        expected_collateral_vault_script_sha256,
        expected_insurance_reserve_script_sha256,
        frozen_bond_asset,
        authenticated_previous_outputs,
        authenticated_opened_previous_outputs,
    )
}

/// Successor-only settlement adapter. Historical V18 callers retain the
/// finite `SignedWithdrawalRequest` API above; this entry point binds the
/// fresh u128-nonce request identity without a narrowing conversion.
#[allow(clippy::too_many_arguments)]
pub fn verify_successor_transition_settlement_v2_with_authenticated_opened_previous_outputs(
    settlement: &TransitionSettlementV2,
    withdrawals: &[SuccessorSignedWithdrawalRequestV2],
    bond_actions: &[BondSettlementActionV2],
    expected_usdd_asset_id: Hash32,
    expected_collateral_vault_script_sha256: Hash32,
    expected_insurance_reserve_script_sha256: Hash32,
    frozen_bond_asset: &FrozenBondAssetV2,
    authenticated_previous_outputs: &[AuthenticatedPreviousOutputV2],
    authenticated_opened_previous_outputs: &[AuthenticatedOpenedPreviousOutputV2],
) -> Result<VerifiedTransitionSettlementV2, SettlementError> {
    let expected_withdrawals: Vec<ExpectedWithdrawalV2> = withdrawals
        .iter()
        .map(|request| ExpectedWithdrawalV2 {
            request_id: request.request.request_id(),
            amount: request.request.amount,
            destination_script_hash: request.request.destination_script_hash,
        })
        .collect();
    verify_transition_settlement_v2_with_expected_withdrawals(
        settlement,
        &expected_withdrawals,
        bond_actions,
        expected_usdd_asset_id,
        expected_collateral_vault_script_sha256,
        expected_insurance_reserve_script_sha256,
        frozen_bond_asset,
        authenticated_previous_outputs,
        authenticated_opened_previous_outputs,
    )
}

#[derive(Debug, Clone, Copy)]
struct ExpectedWithdrawalV2 {
    request_id: Hash32,
    amount: u64,
    destination_script_hash: Hash32,
}

#[allow(clippy::too_many_arguments)]
fn verify_transition_settlement_v2_with_expected_withdrawals(
    settlement: &TransitionSettlementV2,
    withdrawals: &[ExpectedWithdrawalV2],
    bond_actions: &[BondSettlementActionV2],
    expected_usdd_asset_id: Hash32,
    expected_collateral_vault_script_sha256: Hash32,
    expected_insurance_reserve_script_sha256: Hash32,
    frozen_bond_asset: &FrozenBondAssetV2,
    authenticated_previous_outputs: &[AuthenticatedPreviousOutputV2],
    authenticated_opened_previous_outputs: &[AuthenticatedOpenedPreviousOutputV2],
) -> Result<VerifiedTransitionSettlementV2, SettlementError> {
    use std::collections::{BTreeMap, BTreeSet};

    #[derive(Debug, Clone, Copy)]
    struct RedemptionFlow {
        input: u64,
        remainder: Option<u64>,
        inventory_return: Option<u64>,
    }

    if settlement.version != TRANSITION_SETTLEMENT_V2_VERSION {
        return Err(SettlementError::UnsupportedVersion);
    }
    validate_v2_blinding_factors(
        settlement
            .collateral_inputs
            .iter()
            .map(|opening| (opening.asset_blinding_factor, opening.value_blinding_factor))
            .chain(
                settlement
                    .collateral_outputs
                    .iter()
                    .map(|opening| (opening.asset_blinding_factor, opening.value_blinding_factor)),
            )
            .chain(
                settlement
                    .bond_inputs
                    .iter()
                    .map(|opening| (opening.asset_blinding_factor, opening.value_blinding_factor)),
            )
            .chain(
                settlement
                    .bond_outputs
                    .iter()
                    .map(|opening| (opening.asset_blinding_factor, opening.value_blinding_factor)),
            ),
    )?;
    frozen_bond_asset.validate()?;
    if expected_usdd_asset_id == [0; 32]
        || expected_usdd_asset_id == frozen_bond_asset.asset_id
        || expected_collateral_vault_script_sha256 == [0; 32]
        || expected_insurance_reserve_script_sha256 == [0; 32]
        || expected_collateral_vault_script_sha256 == expected_insurance_reserve_script_sha256
    {
        return Err(SettlementError::InvalidBondConfiguration);
    }
    let transaction = decode_transaction(&settlement.transaction)?;
    let (forced_processed_cursor, deposit_processed_cursor) =
        transition_processed_cursors(&transaction)?;
    if transaction.input.len() < 2 || transaction.output.len() < 3 {
        return Err(SettlementError::InvalidSettlementShapeV2);
    }
    if transaction
        .input
        .iter()
        .any(|input| input.has_issuance() || input.is_pegin())
    {
        return Err(SettlementError::BondIssuanceForbidden);
    }
    let mut projected_previous_outputs = BTreeMap::new();
    for projection in authenticated_previous_outputs {
        let input_index = usize::try_from(projection.input_index)
            .map_err(|_| SettlementError::InvalidSettlementShapeV2)?;
        let mut output: TxOut = encode::deserialize(&projection.exact_serialized_txout)
            .map_err(|_| SettlementError::InvalidSettlementShapeV2)?;
        output.witness = encode::deserialize(&projection.exact_serialized_txout_witness)
            .map_err(|_| SettlementError::InvalidSettlementShapeV2)?;
        if input_index < 2
            || projection.previous_txid == [0; 32]
            || projection.previous_vout == u32::MAX
            || projection.exact_serialized_txout.is_empty()
            || projection.exact_serialized_txout_witness.is_empty()
            || projected_previous_outputs
                .insert(
                    input_index,
                    (projection.previous_txid, projection.previous_vout, output),
                )
                .is_some()
        {
            return Err(SettlementError::InvalidSettlementShapeV2);
        }
    }
    let mut used_projected_previous_outputs = BTreeSet::new();
    let mut opened_previous_outputs = BTreeMap::new();
    for projection in authenticated_opened_previous_outputs {
        let input_index = usize::try_from(projection.input_index)
            .map_err(|_| SettlementError::InvalidSettlementShapeV2)?;
        if input_index < 2
            || projection.previous_txid == [0; 32]
            || projection.previous_vout == u32::MAX
            || projection.expected_asset_id == [0; 32]
            || projection.amount == 0
            || projection.script_sha256 == [0; 32]
            || projection.txout_sha256 == [0; 32]
            || projection.txout_witness_sha256 == [0; 32]
            || projected_previous_outputs.contains_key(&input_index)
            || opened_previous_outputs
                .insert(input_index, *projection)
                .is_some()
        {
            return Err(SettlementError::InvalidSettlementShapeV2);
        }
    }
    let mut used_opened_previous_outputs = BTreeSet::new();

    let mut expected_actions = BTreeMap::new();
    for action in bond_actions {
        let action_id = action.action_id();
        if action_id == [0; 32] || expected_actions.insert(action_id, action).is_some() {
            return Err(SettlementError::BondActionMismatch);
        }
        let valid = match *action {
            BondSettlementActionV2::Subscription {
                usdd_contribution_amount,
                bond_share_amount,
                recipient_script_sha256,
                ..
            } => {
                usdd_contribution_amount != 0
                    && bond_share_amount != 0
                    && recipient_script_sha256 != [0; 32]
            }
            BondSettlementActionV2::InsuranceRecapitalizationContribution {
                contribution_id,
                usdd_contribution_amount,
            } => contribution_id != [0; 32] && usdd_contribution_amount != 0,
            BondSettlementActionV2::EnqueueRedemption {
                staging_intent_id,
                claimant,
                bond_share_amount,
                staging_script_sha256,
                source_txid,
                source_vout,
                source_authorization_commitment,
                refund_script_sha256,
                refund_not_before_parent_height,
                destination_script_sha256,
                ..
            } => {
                staging_intent_id != [0; 32]
                    && claimant != [0; 32]
                    && bond_share_amount != 0
                    && staging_script_sha256 != [0; 32]
                    && source_txid != [0; 32]
                    && source_vout != u32::MAX
                    && source_authorization_commitment != [0; 32]
                    && refund_script_sha256 != [0; 32]
                    && refund_not_before_parent_height != 0
                    && destination_script_sha256 != [0; 32]
            }
            BondSettlementActionV2::RefundRejectedEnqueue {
                staging_intent_id,
                claimant,
                bond_share_amount,
                staging_script_sha256,
                source_txid,
                source_vout,
                source_authorization_commitment,
                refund_script_sha256,
                refund_not_before_parent_height,
            } => {
                staging_intent_id != [0; 32]
                    && claimant != [0; 32]
                    && bond_share_amount != 0
                    && staging_script_sha256 != [0; 32]
                    && source_txid != [0; 32]
                    && source_vout != u32::MAX
                    && source_authorization_commitment != [0; 32]
                    && refund_script_sha256 != [0; 32]
                    && refund_not_before_parent_height != 0
            }
            BondSettlementActionV2::CancelRedemption {
                claimant,
                bond_share_amount,
                recipient_script_sha256,
                cancellation_id,
                ..
            } => {
                claimant != [0; 32]
                    && bond_share_amount != 0
                    && recipient_script_sha256 != [0; 32]
                    && cancellation_id != [0; 32]
            }
            BondSettlementActionV2::ExecuteRedemption {
                claimant,
                queued_share_amount,
                redeemed_share_amount,
                remainder_share_amount,
                usdd_payment_amount,
                destination_script_sha256,
                ..
            } => {
                claimant != [0; 32]
                    && queued_share_amount != 0
                    && redeemed_share_amount != 0
                    && usdd_payment_amount != 0
                    && destination_script_sha256 != [0; 32]
                    && redeemed_share_amount
                        .checked_add(remainder_share_amount)
                        .is_some_and(|total| total == queued_share_amount)
            }
        };
        if !valid {
            return Err(SettlementError::BondActionMismatch);
        }
    }
    let mut subscription_usdd_legs = BTreeSet::new();
    let mut subscription_bond_legs = BTreeSet::new();
    let mut recapitalization_usdd_legs = BTreeSet::new();
    let mut enqueue_input_legs = BTreeSet::new();
    let mut enqueue_output_legs = BTreeSet::new();
    let mut rejected_enqueue_input_legs = BTreeSet::new();
    let mut rejected_enqueue_refund_legs = BTreeSet::new();
    let mut cancellation_input_legs = BTreeSet::new();
    let mut cancellation_output_legs = BTreeSet::new();
    let mut execution_input_legs = BTreeSet::new();
    let mut execution_remainder_legs = BTreeSet::new();
    let mut execution_inventory_legs = BTreeSet::new();
    let mut execution_usdd_legs = BTreeSet::new();

    let mut covered_input_indices = BTreeSet::new();
    let mut covered_input_outpoints = BTreeSet::new();
    let mut collateral_input_total = 0u64;
    let mut collateral_vault_input_total = 0u64;
    let mut insurance_reserve_input_total = 0u64;
    let mut collateral_commitments = Vec::new();
    for opening in &settlement.collateral_inputs {
        if opening.amount == 0 {
            return Err(SettlementError::InvalidConfidentialOpening);
        }
        let index = usize::try_from(opening.input_index)
            .map_err(|_| SettlementError::InvalidSettlementShapeV2)?;
        if index < 2 || !covered_input_indices.insert(index) {
            return Err(SettlementError::InvalidSettlementShapeV2);
        }
        let transaction_input = transaction
            .input
            .get(index)
            .ok_or(SettlementError::InvalidSettlementShapeV2)?;
        if projected_previous_outputs.contains_key(&index) {
            return Err(SettlementError::InvalidSettlementShapeV2);
        }
        let (previous_txid, previous_script_sha256) =
            if let Some(projection) = opened_previous_outputs.get(&index) {
                if !opening.previous_transaction.is_empty()
                    || projection.previous_vout != opening.previous_vout
                    || projection.expected_asset_id != expected_usdd_asset_id
                    || projection.amount != opening.amount
                    || !used_opened_previous_outputs.insert(index)
                {
                    return Err(SettlementError::InvalidSettlementShapeV2);
                }
                (projection.previous_txid, projection.script_sha256)
            } else {
                let previous = decode_transaction(&opening.previous_transaction)?;
                let previous_output = previous
                    .output
                    .get(
                        usize::try_from(opening.previous_vout)
                            .map_err(|_| SettlementError::InvalidSettlementShapeV2)?,
                    )
                    .ok_or(SettlementError::InvalidSettlementShapeV2)?;
                verify_output_commitment(
                    previous_output,
                    opening.amount,
                    opening.asset_blinding_factor,
                    opening.value_blinding_factor,
                    expected_usdd_asset_id,
                )?;
                (
                    previous.txid().to_byte_array(),
                    script_sha256(previous_output),
                )
            };
        if transaction_input.previous_output.txid.to_byte_array() != previous_txid
            || transaction_input.previous_output.vout != opening.previous_vout
            || !covered_input_outpoints.insert((previous_txid, opening.previous_vout))
        {
            return Err(SettlementError::InvalidSettlementShapeV2);
        }
        let (role_tag, expected_script) = match opening.role {
            CollateralInputRoleV2::CollateralVault => {
                collateral_vault_input_total = collateral_vault_input_total
                    .checked_add(opening.amount)
                    .ok_or(SettlementError::CollateralConservation)?;
                (0, expected_collateral_vault_script_sha256)
            }
            CollateralInputRoleV2::InsuranceReserve => {
                insurance_reserve_input_total = insurance_reserve_input_total
                    .checked_add(opening.amount)
                    .ok_or(SettlementError::CollateralConservation)?;
                (1, expected_insurance_reserve_script_sha256)
            }
        };
        if previous_script_sha256 != expected_script {
            return Err(SettlementError::WrongVaultScript);
        }
        collateral_input_total = collateral_input_total
            .checked_add(opening.amount)
            .ok_or(SettlementError::CollateralConservation)?;
        let mut preimage = Vec::with_capacity(13);
        preimage.push(role_tag);
        preimage.extend_from_slice(&opening.input_index.to_be_bytes());
        preimage.extend_from_slice(&opening.amount.to_be_bytes());
        collateral_commitments.push(sha256_tagged("ECX/collateral-input/v2", &preimage));
    }

    let mut bond_input_total = 0u64;
    let mut bond_inventory_input_total = 0u64;
    let mut queued_redemption_input_total = 0u64;
    let mut redemptions = BTreeMap::new();
    let mut bond_commitments = Vec::new();
    for opening in &settlement.bond_inputs {
        if opening.amount == 0 {
            return Err(SettlementError::InvalidBondOpening);
        }
        let index = usize::try_from(opening.input_index)
            .map_err(|_| SettlementError::InvalidSettlementShapeV2)?;
        if index < 2 || !covered_input_indices.insert(index) {
            return Err(SettlementError::InvalidSettlementShapeV2);
        }
        let transaction_input = transaction
            .input
            .get(index)
            .ok_or(SettlementError::InvalidSettlementShapeV2)?;
        let previous = if projected_previous_outputs.contains_key(&index)
            || opened_previous_outputs.contains_key(&index)
        {
            None
        } else {
            Some(decode_transaction(&opening.previous_transaction)?)
        };
        let (previous_txid, projected_vout, previous_output, previous_script_sha256) =
            if let Some((txid, vout, output)) = projected_previous_outputs.get(&index) {
                if !opening.previous_transaction.is_empty()
                    || !matches!(
                        opening.role,
                        BondInputRoleV2::StagedRedemptionEnqueue { .. }
                    )
                    || !used_projected_previous_outputs.insert(index)
                {
                    return Err(SettlementError::InvalidSettlementShapeV2);
                }
                (*txid, *vout, Some(output), script_sha256(output))
            } else if let Some(projection) = opened_previous_outputs.get(&index) {
                if !opening.previous_transaction.is_empty()
                    || matches!(
                        opening.role,
                        BondInputRoleV2::StagedRedemptionEnqueue { .. }
                    )
                    || projection.previous_vout != opening.previous_vout
                    || projection.expected_asset_id != frozen_bond_asset.asset_id
                    || projection.amount != opening.amount
                    || !used_opened_previous_outputs.insert(index)
                {
                    return Err(SettlementError::InvalidSettlementShapeV2);
                }
                (
                    projection.previous_txid,
                    projection.previous_vout,
                    None,
                    projection.script_sha256,
                )
            } else {
                let previous = previous
                    .as_ref()
                    .ok_or(SettlementError::InvalidSettlementShapeV2)?;
                let output = previous
                    .output
                    .get(
                        usize::try_from(opening.previous_vout)
                            .map_err(|_| SettlementError::InvalidSettlementShapeV2)?,
                    )
                    .ok_or(SettlementError::InvalidSettlementShapeV2)?;
                (
                    previous.txid().to_byte_array(),
                    opening.previous_vout,
                    Some(output),
                    script_sha256(output),
                )
            };
        if transaction_input.previous_output.txid.to_byte_array() != previous_txid
            || transaction_input.previous_output.vout != projected_vout
            || opening.previous_vout != projected_vout
            || !covered_input_outpoints.insert((previous_txid, opening.previous_vout))
        {
            return Err(SettlementError::InvalidSettlementShapeV2);
        }
        if let Some(previous_output) = previous_output {
            verify_output_commitment(
                previous_output,
                opening.amount,
                opening.asset_blinding_factor,
                opening.value_blinding_factor,
                frozen_bond_asset.asset_id,
            )
            .map_err(|_| SettlementError::InvalidBondOpening)?;
        }

        let mut preimage = Vec::with_capacity(45);
        match opening.role {
            BondInputRoleV2::InventoryVault => {
                if previous_script_sha256 != frozen_bond_asset.inventory_vault_script_sha256 {
                    return Err(SettlementError::WrongBondScript);
                }
                bond_inventory_input_total = bond_inventory_input_total
                    .checked_add(opening.amount)
                    .ok_or(SettlementError::BondConservation)?;
                preimage.push(0);
            }
            BondInputRoleV2::StagedRedemptionEnqueue {
                redemption_id,
                staging_intent_id,
                claimant,
                staging_script_sha256,
                source_txid,
                source_vout,
            } => {
                let settlement_id = if redemption_id == [0; 32] {
                    staging_intent_id
                } else {
                    redemption_id
                };
                let action = expected_actions
                    .get(&settlement_id)
                    .ok_or(SettlementError::BondActionMismatch)?;
                let (
                    expected_staging_intent,
                    expected_claimant,
                    expected_amount,
                    expected_staging_script,
                    expected_source_txid,
                    expected_source_vout,
                    source_authorization_commitment,
                    refund_script_sha256,
                    refund_not_before_parent_height,
                    accepted,
                ) = match **action {
                    BondSettlementActionV2::EnqueueRedemption {
                        staging_intent_id,
                        claimant,
                        bond_share_amount,
                        staging_script_sha256,
                        source_txid,
                        source_vout,
                        source_authorization_commitment,
                        refund_script_sha256,
                        refund_not_before_parent_height,
                        ..
                    } => (
                        staging_intent_id,
                        claimant,
                        bond_share_amount,
                        staging_script_sha256,
                        source_txid,
                        source_vout,
                        source_authorization_commitment,
                        refund_script_sha256,
                        refund_not_before_parent_height,
                        true,
                    ),
                    BondSettlementActionV2::RefundRejectedEnqueue {
                        staging_intent_id,
                        claimant,
                        bond_share_amount,
                        staging_script_sha256,
                        source_txid,
                        source_vout,
                        source_authorization_commitment,
                        refund_script_sha256,
                        refund_not_before_parent_height,
                    } => (
                        staging_intent_id,
                        claimant,
                        bond_share_amount,
                        staging_script_sha256,
                        source_txid,
                        source_vout,
                        source_authorization_commitment,
                        refund_script_sha256,
                        refund_not_before_parent_height,
                        false,
                    ),
                    _ => return Err(SettlementError::BondActionMismatch),
                };
                let previous_output =
                    previous_output.ok_or(SettlementError::InvalidSettlementShapeV2)?;
                let exact_staging_txout = encode::serialize(previous_output);
                if staging_intent_id != expected_staging_intent
                    || claimant != expected_claimant
                    || opening.amount != expected_amount
                    || staging_script_sha256 != expected_staging_script
                    || source_txid != expected_source_txid
                    || source_vout != expected_source_vout
                    || previous_txid != source_txid
                    || opening.previous_vout != source_vout
                    || previous_script_sha256 != staging_script_sha256
                    || staging_script_sha256 == frozen_bond_asset.inventory_vault_script_sha256
                    || staging_script_sha256 == frozen_bond_asset.redemption_queue_script_sha256
                    || bond_inbox_staging_source_authorization_commitment_v2(
                        &exact_staging_txout,
                        staging_intent_id,
                        refund_script_sha256,
                        refund_not_before_parent_height,
                    )? != source_authorization_commitment
                    || if accepted {
                        redemption_id == [0; 32] || !enqueue_input_legs.insert(redemption_id)
                    } else {
                        redemption_id != [0; 32]
                            || !rejected_enqueue_input_legs.insert(staging_intent_id)
                    }
                {
                    return Err(SettlementError::BondActionMismatch);
                }
                preimage.push(1);
                preimage.extend_from_slice(&redemption_id);
                preimage.extend_from_slice(&staging_intent_id);
                preimage.extend_from_slice(&claimant);
                preimage.extend_from_slice(&staging_script_sha256);
                preimage.extend_from_slice(&source_txid);
                preimage.extend_from_slice(&source_vout.to_be_bytes());
            }
            BondInputRoleV2::QueuedRedemption { redemption_id } => {
                if redemption_id == [0; 32] {
                    return Err(SettlementError::BondRedemptionMismatch);
                }
                if previous_script_sha256 != frozen_bond_asset.redemption_queue_script_sha256 {
                    return Err(SettlementError::WrongBondScript);
                }
                match **expected_actions
                    .get(&redemption_id)
                    .ok_or(SettlementError::BondActionMismatch)?
                {
                    BondSettlementActionV2::CancelRedemption {
                        bond_share_amount, ..
                    } => {
                        if opening.amount != bond_share_amount
                            || !cancellation_input_legs.insert(redemption_id)
                        {
                            return Err(SettlementError::BondActionMismatch);
                        }
                    }
                    BondSettlementActionV2::ExecuteRedemption {
                        queued_share_amount,
                        ..
                    } => {
                        if opening.amount != queued_share_amount
                            || !execution_input_legs.insert(redemption_id)
                            || redemptions
                                .insert(
                                    redemption_id,
                                    RedemptionFlow {
                                        input: opening.amount,
                                        remainder: None,
                                        inventory_return: None,
                                    },
                                )
                                .is_some()
                        {
                            return Err(SettlementError::BondActionMismatch);
                        }
                    }
                    _ => return Err(SettlementError::BondActionMismatch),
                }
                queued_redemption_input_total = queued_redemption_input_total
                    .checked_add(opening.amount)
                    .ok_or(SettlementError::BondConservation)?;
                preimage.push(2);
                preimage.extend_from_slice(&redemption_id);
            }
        }
        bond_input_total = bond_input_total
            .checked_add(opening.amount)
            .ok_or(SettlementError::BondConservation)?;
        preimage.extend_from_slice(&opening.input_index.to_be_bytes());
        preimage.extend_from_slice(&opening.amount.to_be_bytes());
        bond_commitments.push(sha256_tagged("ECX/bond-input/v2", &preimage));
    }
    if covered_input_indices.len() != transaction.input.len().saturating_sub(2)
        || !(2..transaction.input.len()).all(|index| covered_input_indices.contains(&index))
        || used_projected_previous_outputs.len() != projected_previous_outputs.len()
        || used_opened_previous_outputs.len() != opened_previous_outputs.len()
    {
        return Err(SettlementError::InvalidSettlementShapeV2);
    }

    let expected_withdrawals: BTreeMap<Hash32, &ExpectedWithdrawalV2> = withdrawals
        .iter()
        .map(|request| (request.request_id, request))
        .collect();
    if expected_withdrawals.len() != withdrawals.len() {
        return Err(SettlementError::WithdrawalMismatch);
    }
    let mut covered_withdrawals = BTreeSet::new();
    let mut covered_output_indices = BTreeSet::new();
    let mut collateral_output_total = 0u64;
    let mut collateral_vault_change_total = 0u64;
    let mut insurance_reserve_output_total = 0u64;
    let mut subscription_contribution_total = 0u64;
    let mut recapitalization_contribution_total = 0u64;
    let mut redemption_payment_total = 0u64;
    let mut withdrawal_total = 0u64;
    let mut collateral_subscription_ids = BTreeSet::new();
    let mut redemption_payment_ids = BTreeSet::new();
    for opening in &settlement.collateral_outputs {
        if opening.amount == 0 {
            return Err(SettlementError::InvalidConfidentialOpening);
        }
        let index = usize::try_from(opening.output_index)
            .map_err(|_| SettlementError::InvalidSettlementShapeV2)?;
        if !covered_output_indices.insert(index) {
            return Err(SettlementError::InvalidSettlementShapeV2);
        }
        let output = transaction
            .output
            .get(index)
            .ok_or(SettlementError::InvalidSettlementShapeV2)?;
        verify_output_commitment(
            output,
            opening.amount,
            opening.asset_blinding_factor,
            opening.value_blinding_factor,
            expected_usdd_asset_id,
        )?;
        let mut preimage = Vec::with_capacity(77);
        match opening.role {
            CollateralOutputRoleV2::CollateralVaultChange => {
                if script_sha256(output) != expected_collateral_vault_script_sha256 {
                    return Err(SettlementError::WrongVaultScript);
                }
                collateral_vault_change_total = collateral_vault_change_total
                    .checked_add(opening.amount)
                    .ok_or(SettlementError::CollateralConservation)?;
                preimage.push(0);
            }
            CollateralOutputRoleV2::InsuranceReserveChange => {
                if script_sha256(output) != expected_insurance_reserve_script_sha256 {
                    return Err(SettlementError::WrongVaultScript);
                }
                insurance_reserve_output_total = insurance_reserve_output_total
                    .checked_add(opening.amount)
                    .ok_or(SettlementError::CollateralConservation)?;
                preimage.push(1);
            }
            CollateralOutputRoleV2::BondSubscriptionContribution { subscription_id } => {
                let matches_action = expected_actions
                    .get(&subscription_id)
                    .is_some_and(|action| {
                        matches!(
                            **action,
                            BondSettlementActionV2::Subscription {
                                usdd_contribution_amount,
                                ..
                            } if usdd_contribution_amount == opening.amount
                        )
                    });
                if !matches_action
                    || !collateral_subscription_ids.insert(subscription_id)
                    || !subscription_usdd_legs.insert(subscription_id)
                    || script_sha256(output) != expected_insurance_reserve_script_sha256
                {
                    return Err(SettlementError::BondActionMismatch);
                }
                insurance_reserve_output_total = insurance_reserve_output_total
                    .checked_add(opening.amount)
                    .ok_or(SettlementError::CollateralConservation)?;
                subscription_contribution_total = subscription_contribution_total
                    .checked_add(opening.amount)
                    .ok_or(SettlementError::CollateralConservation)?;
                preimage.push(2);
                preimage.extend_from_slice(&subscription_id);
            }
            CollateralOutputRoleV2::InsuranceRecapitalizationContribution { contribution_id } => {
                let matches_action = expected_actions
                    .get(&contribution_id)
                    .is_some_and(|action| {
                        matches!(
                            **action,
                            BondSettlementActionV2::InsuranceRecapitalizationContribution {
                                usdd_contribution_amount,
                                ..
                            } if usdd_contribution_amount == opening.amount
                        )
                    });
                if !matches_action
                    || !recapitalization_usdd_legs.insert(contribution_id)
                    || script_sha256(output) != expected_insurance_reserve_script_sha256
                {
                    return Err(SettlementError::BondActionMismatch);
                }
                insurance_reserve_output_total = insurance_reserve_output_total
                    .checked_add(opening.amount)
                    .ok_or(SettlementError::CollateralConservation)?;
                recapitalization_contribution_total = recapitalization_contribution_total
                    .checked_add(opening.amount)
                    .ok_or(SettlementError::CollateralConservation)?;
                preimage.push(5);
                preimage.extend_from_slice(&contribution_id);
            }
            CollateralOutputRoleV2::BondRedemptionPayment {
                redemption_id,
                recipient_script_sha256,
            } => {
                let matches_action = expected_actions.get(&redemption_id).is_some_and(|action| {
                    matches!(
                        **action,
                        BondSettlementActionV2::ExecuteRedemption {
                            usdd_payment_amount,
                            destination_script_sha256,
                            ..
                        } if usdd_payment_amount == opening.amount
                            && destination_script_sha256 == recipient_script_sha256
                    )
                });
                if !matches_action
                    || !redemption_payment_ids.insert(redemption_id)
                    || !execution_usdd_legs.insert(redemption_id)
                    || script_sha256(output) != recipient_script_sha256
                {
                    return Err(SettlementError::BondActionMismatch);
                }
                redemption_payment_total = redemption_payment_total
                    .checked_add(opening.amount)
                    .ok_or(SettlementError::CollateralConservation)?;
                preimage.push(3);
                preimage.extend_from_slice(&redemption_id);
                preimage.extend_from_slice(&recipient_script_sha256);
            }
            CollateralOutputRoleV2::Withdrawal { request_id } => {
                let request = expected_withdrawals
                    .get(&request_id)
                    .ok_or(SettlementError::WithdrawalMismatch)?;
                if !covered_withdrawals.insert(request_id)
                    || request.amount != opening.amount
                    || script_sha256(output) != request.destination_script_hash
                {
                    return Err(SettlementError::WithdrawalMismatch);
                }
                withdrawal_total = withdrawal_total
                    .checked_add(opening.amount)
                    .ok_or(SettlementError::CollateralConservation)?;
                preimage.push(4);
                preimage.extend_from_slice(&request_id);
            }
        }
        collateral_output_total = collateral_output_total
            .checked_add(opening.amount)
            .ok_or(SettlementError::CollateralConservation)?;
        preimage.extend_from_slice(&opening.output_index.to_be_bytes());
        preimage.extend_from_slice(&opening.amount.to_be_bytes());
        collateral_commitments.push(sha256_tagged("ECX/collateral-output/v2", &preimage));
    }
    if covered_withdrawals.len() != expected_withdrawals.len() {
        return Err(SettlementError::WithdrawalMismatch);
    }

    let mut bond_output_total = 0u64;
    let mut bond_inventory_change_total = 0u64;
    let mut bond_subscription_total = 0u64;
    let mut redemption_remainder_total = 0u64;
    let mut redemption_inventory_return_total = 0u64;
    let mut rejected_enqueue_refund_total = 0u64;
    let mut bond_subscription_ids = BTreeSet::new();
    let mut redemption_inventory_return_ids = BTreeSet::new();
    for opening in &settlement.bond_outputs {
        if opening.amount == 0 {
            return Err(SettlementError::InvalidBondOpening);
        }
        let index = usize::try_from(opening.output_index)
            .map_err(|_| SettlementError::InvalidSettlementShapeV2)?;
        if !covered_output_indices.insert(index) {
            return Err(SettlementError::InvalidSettlementShapeV2);
        }
        let output = transaction
            .output
            .get(index)
            .ok_or(SettlementError::InvalidSettlementShapeV2)?;
        verify_output_commitment(
            output,
            opening.amount,
            opening.asset_blinding_factor,
            opening.value_blinding_factor,
            frozen_bond_asset.asset_id,
        )
        .map_err(|_| SettlementError::InvalidBondOpening)?;

        let mut preimage = Vec::with_capacity(77);
        match opening.role {
            BondOutputRoleV2::InventoryVaultChange => {
                if script_sha256(output) != frozen_bond_asset.inventory_vault_script_sha256 {
                    return Err(SettlementError::WrongBondScript);
                }
                bond_inventory_change_total = bond_inventory_change_total
                    .checked_add(opening.amount)
                    .ok_or(SettlementError::BondConservation)?;
                preimage.push(0);
            }
            BondOutputRoleV2::Subscription {
                subscription_id,
                recipient_script_sha256,
            } => {
                let matches_action = expected_actions
                    .get(&subscription_id)
                    .is_some_and(|action| {
                        matches!(
                            **action,
                            BondSettlementActionV2::Subscription {
                                bond_share_amount,
                                recipient_script_sha256: expected_recipient,
                                ..
                            } if bond_share_amount == opening.amount
                                && expected_recipient == recipient_script_sha256
                        )
                    });
                if !matches_action
                    || recipient_script_sha256 == frozen_bond_asset.inventory_vault_script_sha256
                    || recipient_script_sha256 == frozen_bond_asset.redemption_queue_script_sha256
                    || script_sha256(output) != recipient_script_sha256
                    || !bond_subscription_ids.insert(subscription_id)
                    || !subscription_bond_legs.insert(subscription_id)
                {
                    return Err(SettlementError::BondActionMismatch);
                }
                bond_subscription_total = bond_subscription_total
                    .checked_add(opening.amount)
                    .ok_or(SettlementError::BondConservation)?;
                preimage.push(1);
                preimage.extend_from_slice(&subscription_id);
                preimage.extend_from_slice(&recipient_script_sha256);
            }
            BondOutputRoleV2::QueuedRedemptionEntry {
                redemption_id,
                staging_intent_id,
                claimant,
                destination_script_sha256,
            } => {
                let matches_action = expected_actions.get(&redemption_id).is_some_and(|action| {
                    matches!(
                        **action,
                        BondSettlementActionV2::EnqueueRedemption {
                            staging_intent_id: expected_staging_intent,
                            claimant: expected_claimant,
                            bond_share_amount,
                            destination_script_sha256: expected_destination,
                            ..
                        } if expected_staging_intent == staging_intent_id
                            && expected_claimant == claimant
                            && bond_share_amount == opening.amount
                            && expected_destination == destination_script_sha256
                    )
                });
                if !matches_action
                    || script_sha256(output) != frozen_bond_asset.redemption_queue_script_sha256
                    || !enqueue_output_legs.insert(redemption_id)
                {
                    return Err(SettlementError::BondActionMismatch);
                }
                preimage.push(2);
                preimage.extend_from_slice(&redemption_id);
                preimage.extend_from_slice(&staging_intent_id);
                preimage.extend_from_slice(&claimant);
                preimage.extend_from_slice(&destination_script_sha256);
            }
            BondOutputRoleV2::QueuedRedemptionRemainder { .. } => {
                return Err(SettlementError::BondActionMismatch);
            }
            BondOutputRoleV2::AuthenticatedQueuedRedemptionRemainder {
                redemption_id,
                claimant,
                destination_script_sha256,
            } => {
                if script_sha256(output) != frozen_bond_asset.redemption_queue_script_sha256 {
                    return Err(SettlementError::WrongBondScript);
                }
                let matches_action = expected_actions.get(&redemption_id).is_some_and(|action| {
                    matches!(
                        **action,
                        BondSettlementActionV2::ExecuteRedemption {
                            claimant: expected_claimant,
                            remainder_share_amount,
                            destination_script_sha256: expected_destination,
                            ..
                        } if expected_claimant == claimant
                            && remainder_share_amount == opening.amount
                            && expected_destination == destination_script_sha256
                    )
                });
                let flow = redemptions
                    .get_mut(&redemption_id)
                    .ok_or(SettlementError::BondRedemptionMismatch)?;
                if !matches_action
                    || flow.remainder.replace(opening.amount).is_some()
                    || !execution_remainder_legs.insert(redemption_id)
                {
                    return Err(SettlementError::BondRedemptionMismatch);
                }
                redemption_remainder_total = redemption_remainder_total
                    .checked_add(opening.amount)
                    .ok_or(SettlementError::BondConservation)?;
                preimage.push(3);
                preimage.extend_from_slice(&redemption_id);
                preimage.extend_from_slice(&claimant);
                preimage.extend_from_slice(&destination_script_sha256);
            }
            BondOutputRoleV2::RedemptionInventoryReturn { redemption_id } => {
                let matches_action = expected_actions.get(&redemption_id).is_some_and(|action| {
                    matches!(
                        **action,
                        BondSettlementActionV2::ExecuteRedemption {
                            redeemed_share_amount,
                            ..
                        } if redeemed_share_amount == opening.amount
                    )
                });
                if script_sha256(output) != frozen_bond_asset.inventory_vault_script_sha256
                    || !matches_action
                    || !redemption_inventory_return_ids.insert(redemption_id)
                    || !execution_inventory_legs.insert(redemption_id)
                {
                    return Err(SettlementError::BondRedemptionMismatch);
                }
                let flow = redemptions
                    .get_mut(&redemption_id)
                    .ok_or(SettlementError::BondRedemptionMismatch)?;
                if flow.inventory_return.replace(opening.amount).is_some() {
                    return Err(SettlementError::BondRedemptionMismatch);
                }
                redemption_inventory_return_total = redemption_inventory_return_total
                    .checked_add(opening.amount)
                    .ok_or(SettlementError::BondConservation)?;
                preimage.push(4);
                preimage.extend_from_slice(&redemption_id);
            }
            BondOutputRoleV2::CancelledRedemptionReturn {
                redemption_id,
                claimant,
                recipient_script_sha256,
                cancellation_id,
            } => {
                let matches_action = expected_actions.get(&redemption_id).is_some_and(|action| {
                    matches!(
                        **action,
                        BondSettlementActionV2::CancelRedemption {
                            claimant: expected_claimant,
                            bond_share_amount,
                            recipient_script_sha256: expected_recipient,
                            cancellation_id: expected_cancellation,
                            ..
                        } if expected_claimant == claimant
                            && bond_share_amount == opening.amount
                            && expected_recipient == recipient_script_sha256
                            && expected_cancellation == cancellation_id
                    )
                });
                if !matches_action
                    || recipient_script_sha256 == frozen_bond_asset.inventory_vault_script_sha256
                    || recipient_script_sha256 == frozen_bond_asset.redemption_queue_script_sha256
                    || script_sha256(output) != recipient_script_sha256
                    || !cancellation_output_legs.insert(redemption_id)
                {
                    return Err(SettlementError::BondActionMismatch);
                }
                preimage.push(5);
                preimage.extend_from_slice(&redemption_id);
                preimage.extend_from_slice(&claimant);
                preimage.extend_from_slice(&recipient_script_sha256);
                preimage.extend_from_slice(&cancellation_id);
            }
            BondOutputRoleV2::RejectedEnqueueRefund {
                staging_intent_id,
                claimant,
                recipient_script_sha256,
            } => {
                let matches_action =
                    expected_actions
                        .get(&staging_intent_id)
                        .is_some_and(|action| {
                            matches!(
                                **action,
                                BondSettlementActionV2::RefundRejectedEnqueue {
                                    claimant: expected_claimant,
                                    bond_share_amount,
                                    refund_script_sha256,
                                    ..
                                } if expected_claimant == claimant
                                    && bond_share_amount == opening.amount
                                    && refund_script_sha256 == recipient_script_sha256
                            )
                        });
                if !matches_action
                    || recipient_script_sha256 == frozen_bond_asset.inventory_vault_script_sha256
                    || recipient_script_sha256 == frozen_bond_asset.redemption_queue_script_sha256
                    || script_sha256(output) != recipient_script_sha256
                    || !rejected_enqueue_refund_legs.insert(staging_intent_id)
                {
                    return Err(SettlementError::BondActionMismatch);
                }
                rejected_enqueue_refund_total = rejected_enqueue_refund_total
                    .checked_add(opening.amount)
                    .ok_or(SettlementError::BondConservation)?;
                preimage.push(6);
                preimage.extend_from_slice(&staging_intent_id);
                preimage.extend_from_slice(&claimant);
                preimage.extend_from_slice(&recipient_script_sha256);
            }
        }
        bond_output_total = bond_output_total
            .checked_add(opening.amount)
            .ok_or(SettlementError::BondConservation)?;
        preimage.extend_from_slice(&opening.output_index.to_be_bytes());
        preimage.extend_from_slice(&opening.amount.to_be_bytes());
        bond_commitments.push(sha256_tagged("ECX/bond-output/v2", &preimage));
    }

    // Every confidential output must belong to exactly one of the two opened
    // asset sets. Neither USDD nor the frozen bond may appear explicitly.
    for (index, output) in transaction.output.iter().enumerate() {
        let confidential = output.asset.is_confidential()
            || output.value.is_confidential()
            || output.nonce.is_confidential();
        if confidential != covered_output_indices.contains(&index) {
            return Err(SettlementError::InvalidSettlementShapeV2);
        }
        if let Some(asset) = output.asset.explicit() {
            let asset_id = asset.into_inner().to_byte_array();
            if asset_id == expected_usdd_asset_id || asset_id == frozen_bond_asset.asset_id {
                return Err(SettlementError::InvalidSettlementShapeV2);
            }
        }
    }
    if collateral_input_total != collateral_output_total
        || withdrawal_total
            != withdrawals
                .iter()
                .try_fold(0u64, |sum, request| sum.checked_add(request.amount))
                .ok_or(SettlementError::CollateralConservation)?
    {
        return Err(SettlementError::CollateralConservation);
    }
    if bond_inventory_input_total
        != bond_inventory_change_total
            .checked_add(bond_subscription_total)
            .ok_or(SettlementError::BondConservation)?
    {
        return Err(SettlementError::BondConservation);
    }
    for flow in redemptions.values() {
        let inventory_return = flow
            .inventory_return
            .ok_or(SettlementError::BondRedemptionMismatch)?;
        if flow
            .remainder
            .unwrap_or(0)
            .checked_add(inventory_return)
            .filter(|total| *total == flow.input)
            .is_none()
        {
            return Err(SettlementError::BondRedemptionMismatch);
        }
    }
    if bond_input_total != bond_output_total
        || bond_input_total > FrozenBondAssetV2::FIXED_SUPPLY_ATOMS
    {
        return Err(SettlementError::BondConservation);
    }
    if collateral_subscription_ids != bond_subscription_ids
        || redemption_payment_ids != redemption_inventory_return_ids
    {
        return Err(SettlementError::BondActionMismatch);
    }
    for action in bond_actions {
        let action_id = action.action_id();
        let covered = match *action {
            BondSettlementActionV2::Subscription { .. } => {
                subscription_usdd_legs.contains(&action_id)
                    && subscription_bond_legs.contains(&action_id)
            }
            BondSettlementActionV2::InsuranceRecapitalizationContribution { .. } => {
                recapitalization_usdd_legs.contains(&action_id)
            }
            BondSettlementActionV2::EnqueueRedemption { .. } => {
                enqueue_input_legs.contains(&action_id) && enqueue_output_legs.contains(&action_id)
            }
            BondSettlementActionV2::RefundRejectedEnqueue { .. } => {
                rejected_enqueue_input_legs.contains(&action_id)
                    && rejected_enqueue_refund_legs.contains(&action_id)
            }
            BondSettlementActionV2::CancelRedemption { .. } => {
                cancellation_input_legs.contains(&action_id)
                    && cancellation_output_legs.contains(&action_id)
            }
            BondSettlementActionV2::ExecuteRedemption {
                remainder_share_amount,
                ..
            } => {
                execution_input_legs.contains(&action_id)
                    && execution_inventory_legs.contains(&action_id)
                    && execution_usdd_legs.contains(&action_id)
                    && (remainder_share_amount == 0
                        || execution_remainder_legs.contains(&action_id))
            }
        };
        if !covered {
            return Err(SettlementError::BondActionMismatch);
        }
    }

    collateral_commitments.sort_unstable();
    bond_commitments.sort_unstable();
    let transition_txid = transaction.txid().to_byte_array();
    let mut collateral_preimage = Vec::with_capacity(32 + collateral_commitments.len() * 32);
    collateral_preimage.extend_from_slice(&transition_txid);
    collateral_preimage.extend_from_slice(&collateral_commitments.concat());
    let collateral_settlement_root =
        sha256_tagged("ECX/collateral-settlement/v2", &collateral_preimage);
    let mut bond_preimage = Vec::with_capacity(32 + bond_commitments.len() * 32);
    bond_preimage.extend_from_slice(&transition_txid);
    bond_preimage.extend_from_slice(&bond_commitments.concat());
    let bond_settlement_root = sha256_tagged("ECX/bond-settlement/v2", &bond_preimage);
    let mut combined_preimage = Vec::with_capacity(96);
    combined_preimage.extend_from_slice(&transition_txid);
    combined_preimage.extend_from_slice(&collateral_settlement_root);
    combined_preimage.extend_from_slice(&bond_settlement_root);

    Ok(VerifiedTransitionSettlementV2 {
        transition_txid,
        forced_processed_cursor,
        deposit_processed_cursor,
        collateral_input_total,
        collateral_output_total,
        collateral_vault_input_total,
        insurance_reserve_input_total,
        collateral_vault_change_total,
        insurance_reserve_output_total,
        subscription_contribution_total,
        recapitalization_contribution_total,
        redemption_payment_total,
        withdrawal_total,
        bond_input_total,
        bond_output_total,
        bond_inventory_input_total,
        bond_inventory_change_total,
        bond_subscription_total,
        queued_redemption_input_total,
        redemption_remainder_total,
        redemption_inventory_return_total,
        rejected_enqueue_refund_total,
        collateral_settlement_root,
        bond_settlement_root,
        combined_settlement_root: sha256_tagged("ECX/combined-settlement/v2", &combined_preimage),
    })
}

/// Authenticate the one-time issuance that defines the frozen v2 bond asset.
///
/// The asset id and reissuance-token id are derived with the Elements library
/// from the issuance input's previous outpoint and contract entropy. The full
/// bond supply is a confidential issuance pseudo-input whose opening balances
/// the confidential inventory output; an explicit issuance paired with a
/// nonzero inventory blinder fails Elements' Pedersen conservation equation.
/// The sole reissuance token is explicit and permanently destroyed by the
/// configured `OP_RETURN` output. All later movement uses
/// `verify_bond_settlement_v2`, which rejects issuance fields entirely.
pub fn verify_frozen_bond_deployment_v2(
    deployment: &FrozenBondDeploymentV2,
    frozen_asset: &FrozenBondAssetV2,
) -> Result<VerifiedFrozenBondDeploymentV2, SettlementError> {
    if deployment.version != BOND_DEPLOYMENT_VERSION {
        return Err(SettlementError::UnsupportedVersion);
    }
    validate_v2_blinding_factors(std::iter::once((
        deployment.inventory_asset_blinding_factor,
        deployment.inventory_value_blinding_factor,
    )))?;
    if deployment.issuance_value_blinding_factor == [0; 32]
        || deployment.issuance_value_blinding_factor == deployment.inventory_asset_blinding_factor
        || deployment.issuance_value_blinding_factor == deployment.inventory_value_blinding_factor
    {
        return Err(SettlementError::UnsafeBlindingFactorsV2);
    }
    frozen_asset.validate()?;
    let transaction = decode_transaction(&deployment.transaction)?;
    if transaction.input.is_empty()
        || transaction.output.is_empty()
        || transaction.input.iter().any(|input| input.is_pegin())
        || transaction
            .input
            .iter()
            .filter(|input| input.has_issuance())
            .count()
            != 1
    {
        return Err(SettlementError::InvalidBondDeployment);
    }

    let issuance_input_index = usize::try_from(deployment.issuance_input_index)
        .map_err(|_| SettlementError::InvalidBondDeployment)?;
    let issuance_input = transaction
        .input
        .get(issuance_input_index)
        .ok_or(SettlementError::InvalidBondDeployment)?;
    if !issuance_input.has_issuance()
        || issuance_input.asset_issuance.asset_blinding_nonce != elements::secp256k1_zkp::ZERO_TWEAK
        || issuance_input.asset_issuance.inflation_keys
            != Value::Explicit(BOND_REISSUANCE_TOKEN_BURN_AMOUNT_V2)
        || issuance_input.witness.amount_rangeproof.is_none()
        || issuance_input.witness.inflation_keys_rangeproof.is_some()
    {
        return Err(SettlementError::InvalidBondDeployment);
    }
    let (derived_bond_asset, derived_reissuance_token) = issuance_input.issuance_ids();
    let bond_asset_id = derived_bond_asset.into_inner().to_byte_array();
    let reissuance_token_asset_id = derived_reissuance_token.into_inner().to_byte_array();
    if bond_asset_id != frozen_asset.asset_id || reissuance_token_asset_id == bond_asset_id {
        return Err(SettlementError::InvalidBondDeployment);
    }
    let secp = Secp256k1::new();
    let issuance_vbf = ValueBlindingFactor::from_slice(&deployment.issuance_value_blinding_factor)
        .map_err(|_| SettlementError::InvalidBondDeployment)?;
    let issuance_asset =
        Asset::new_confidential(&secp, derived_bond_asset, AssetBlindingFactor::zero());
    let issuance_generator = issuance_asset
        .commitment()
        .ok_or(SettlementError::InvalidBondDeployment)?;
    let expected_issuance_value = Value::new_confidential(
        &secp,
        FrozenBondAssetV2::FIXED_SUPPLY_ATOMS,
        issuance_generator,
        issuance_vbf,
    );
    if issuance_input.asset_issuance.amount != expected_issuance_value {
        return Err(SettlementError::InvalidBondDeployment);
    }
    let issuance_commitment = expected_issuance_value
        .commitment()
        .ok_or(SettlementError::InvalidBondDeployment)?;
    let issuance_range = issuance_input
        .witness
        .amount_rangeproof
        .as_ref()
        .ok_or(SettlementError::InvalidBondDeployment)?
        .verify(&secp, issuance_commitment, &[], issuance_generator)
        .map_err(|_| SettlementError::InvalidBondDeployment)?;
    if FrozenBondAssetV2::FIXED_SUPPLY_ATOMS < issuance_range.start
        || FrozenBondAssetV2::FIXED_SUPPLY_ATOMS >= issuance_range.end
    {
        return Err(SettlementError::InvalidBondDeployment);
    }

    let inventory_index = usize::try_from(deployment.inventory_output_index)
        .map_err(|_| SettlementError::InvalidBondDeployment)?;
    let burn_index = usize::try_from(deployment.reissuance_token_burn_output_index)
        .map_err(|_| SettlementError::InvalidBondDeployment)?;
    if inventory_index == burn_index {
        return Err(SettlementError::InvalidBondDeployment);
    }
    let inventory_output = transaction
        .output
        .get(inventory_index)
        .ok_or(SettlementError::InvalidBondDeployment)?;
    verify_output_commitment(
        inventory_output,
        FrozenBondAssetV2::FIXED_SUPPLY_ATOMS,
        deployment.inventory_asset_blinding_factor,
        deployment.inventory_value_blinding_factor,
        frozen_asset.asset_id,
    )
    .map_err(|_| SettlementError::InvalidBondOpening)?;
    if script_sha256(inventory_output) != frozen_asset.inventory_vault_script_sha256 {
        return Err(SettlementError::WrongBondScript);
    }

    let burn_output = transaction
        .output
        .get(burn_index)
        .ok_or(SettlementError::InvalidBondDeployment)?;
    if explicit_output_amount(burn_output, reissuance_token_asset_id)
        != Some(BOND_REISSUANCE_TOKEN_BURN_AMOUNT_V2)
        || burn_output.nonce != Nonce::Null
        || script_sha256(burn_output) != frozen_asset.reissuance_token_burn_script_sha256
        || !is_provably_unspendable_script(burn_output.script_pubkey.as_bytes())
    {
        return Err(SettlementError::BondReissuanceTokenNotDestroyed);
    }

    // The deployment transaction is deliberately transparent except for the
    // full-supply inventory output. This makes an extra hidden bond/token
    // output impossible at this boundary and keeps sponsor/fee outputs public.
    for (index, output) in transaction.output.iter().enumerate() {
        let confidential = output.asset.is_confidential()
            || output.value.is_confidential()
            || output.nonce.is_confidential();
        if index == inventory_index {
            if !confidential {
                return Err(SettlementError::InvalidBondOpening);
            }
            continue;
        }
        if confidential {
            return Err(SettlementError::InvalidBondDeployment);
        }
        if let Some(asset) = output.asset.explicit() {
            let asset_id = asset.into_inner().to_byte_array();
            if asset_id == frozen_asset.asset_id {
                return Err(SettlementError::InvalidBondDeployment);
            }
            if asset_id == reissuance_token_asset_id && index != burn_index {
                return Err(SettlementError::BondReissuanceTokenNotDestroyed);
            }
        }
    }

    let transaction_id = transaction.txid().to_byte_array();
    let mut commitment_preimage = Vec::with_capacity(253);
    commitment_preimage.push(deployment.version);
    commitment_preimage.extend_from_slice(&transaction_id);
    commitment_preimage.extend_from_slice(&issuance_input.previous_output.txid.to_byte_array());
    commitment_preimage.extend_from_slice(&issuance_input.previous_output.vout.to_be_bytes());
    commitment_preimage.extend_from_slice(&bond_asset_id);
    commitment_preimage.extend_from_slice(&reissuance_token_asset_id);
    commitment_preimage.extend_from_slice(&FrozenBondAssetV2::FIXED_SUPPLY_ATOMS.to_be_bytes());
    commitment_preimage.extend_from_slice(&deployment.inventory_output_index.to_be_bytes());
    commitment_preimage
        .extend_from_slice(&deployment.reissuance_token_burn_output_index.to_be_bytes());
    commitment_preimage.extend_from_slice(&frozen_asset.inventory_vault_script_sha256);
    commitment_preimage.extend_from_slice(&frozen_asset.reissuance_token_burn_script_sha256);

    Ok(VerifiedFrozenBondDeploymentV2 {
        transaction_id,
        issuance_previous_txid: issuance_input.previous_output.txid.to_byte_array(),
        issuance_previous_vout: issuance_input.previous_output.vout,
        bond_asset_id,
        reissuance_token_asset_id,
        inventory_output_index: deployment.inventory_output_index,
        reissuance_token_burn_output_index: deployment.reissuance_token_burn_output_index,
        fixed_supply_atoms: FrozenBondAssetV2::FIXED_SUPPLY_ATOMS,
        deployment_commitment: sha256_tagged("ECX/frozen-bond-deployment/v2", &commitment_preimage),
    })
}

/// Verify one post-deployment confidential bond movement transaction.
///
/// This relation intentionally does not authorize the original asset
/// issuance. It binds every opened share to the frozen asset id, forbids all
/// issuance/reissuance flags, fixes inventory and queue scripts, accounts for
/// every confidential output, and conserves shares both globally and by
/// action. Solvency, NAV, queue age/FIFO order, and USDD consideration remain
/// transition-proof responsibilities and can consume the returned totals and
/// root without reinterpreting the Elements transaction.
pub fn verify_bond_settlement_v2(
    settlement: &BondSettlementV2,
    frozen_asset: &FrozenBondAssetV2,
) -> Result<VerifiedBondSettlementV2, SettlementError> {
    use std::collections::{BTreeMap, BTreeSet};

    #[derive(Debug, Clone, Copy)]
    struct RedemptionFlow {
        input: u64,
        remainder: Option<u64>,
        inventory_return: Option<u64>,
    }

    if settlement.version != BOND_SETTLEMENT_VERSION {
        return Err(SettlementError::UnsupportedVersion);
    }
    validate_v2_blinding_factors(
        settlement
            .bond_inputs
            .iter()
            .map(|opening| (opening.asset_blinding_factor, opening.value_blinding_factor))
            .chain(
                settlement
                    .bond_outputs
                    .iter()
                    .map(|opening| (opening.asset_blinding_factor, opening.value_blinding_factor)),
            ),
    )?;
    frozen_asset.validate()?;
    let transaction = decode_transaction(&settlement.transaction)?;
    if transaction.input.is_empty()
        || transaction.output.is_empty()
        || settlement.bond_inputs.is_empty()
        || settlement.bond_outputs.is_empty()
    {
        return Err(SettlementError::InvalidBondSettlementShape);
    }
    if transaction
        .input
        .iter()
        .any(|input| input.has_issuance() || input.is_pegin())
    {
        return Err(SettlementError::BondIssuanceForbidden);
    }

    let mut input_indices = BTreeSet::new();
    let mut input_outpoints = BTreeSet::new();
    let mut input_commitments = Vec::new();
    let mut redemptions = BTreeMap::new();
    let mut bond_input_total = 0u64;
    let mut inventory_input_total = 0u64;
    let mut queued_redemption_input_total = 0u64;

    for opening in &settlement.bond_inputs {
        if opening.amount == 0 {
            return Err(SettlementError::InvalidBondOpening);
        }
        let index = usize::try_from(opening.input_index)
            .map_err(|_| SettlementError::InvalidBondSettlementShape)?;
        if !input_indices.insert(index) {
            return Err(SettlementError::InvalidBondSettlementShape);
        }
        let transaction_input = transaction
            .input
            .get(index)
            .ok_or(SettlementError::InvalidBondSettlementShape)?;
        let previous = decode_transaction(&opening.previous_transaction)?;
        let previous_txid = previous.txid();
        if transaction_input.previous_output.txid != previous_txid
            || transaction_input.previous_output.vout != opening.previous_vout
            || !input_outpoints.insert((previous_txid.to_byte_array(), opening.previous_vout))
        {
            return Err(SettlementError::InvalidBondSettlementShape);
        }
        let previous_output = previous
            .output
            .get(
                usize::try_from(opening.previous_vout)
                    .map_err(|_| SettlementError::InvalidBondSettlementShape)?,
            )
            .ok_or(SettlementError::InvalidBondSettlementShape)?;
        verify_output_commitment(
            previous_output,
            opening.amount,
            opening.asset_blinding_factor,
            opening.value_blinding_factor,
            frozen_asset.asset_id,
        )
        .map_err(|_| SettlementError::InvalidBondOpening)?;

        let mut role_commitment = Vec::with_capacity(65);
        match opening.role {
            BondInputRoleV2::InventoryVault => {
                if script_sha256(previous_output) != frozen_asset.inventory_vault_script_sha256 {
                    return Err(SettlementError::WrongBondScript);
                }
                inventory_input_total = inventory_input_total
                    .checked_add(opening.amount)
                    .ok_or(SettlementError::BondConservation)?;
                role_commitment.push(0);
            }
            BondInputRoleV2::StagedRedemptionEnqueue { .. } => {
                return Err(SettlementError::InvalidBondSettlementShape);
            }
            BondInputRoleV2::QueuedRedemption { redemption_id } => {
                if redemption_id == [0; 32] {
                    return Err(SettlementError::BondRedemptionMismatch);
                }
                if script_sha256(previous_output) != frozen_asset.redemption_queue_script_sha256 {
                    return Err(SettlementError::WrongBondScript);
                }
                if redemptions
                    .insert(
                        redemption_id,
                        RedemptionFlow {
                            input: opening.amount,
                            remainder: None,
                            inventory_return: None,
                        },
                    )
                    .is_some()
                {
                    return Err(SettlementError::BondRedemptionMismatch);
                }
                queued_redemption_input_total = queued_redemption_input_total
                    .checked_add(opening.amount)
                    .ok_or(SettlementError::BondConservation)?;
                role_commitment.push(1);
                role_commitment.extend_from_slice(&redemption_id);
            }
        }
        bond_input_total = bond_input_total
            .checked_add(opening.amount)
            .ok_or(SettlementError::BondConservation)?;
        role_commitment.extend_from_slice(&opening.input_index.to_be_bytes());
        role_commitment.extend_from_slice(&opening.amount.to_be_bytes());
        input_commitments.push(sha256_tagged("ECX/bond-input/v2", &role_commitment));
    }

    let mut output_indices = BTreeSet::new();
    let mut subscription_ids = BTreeSet::new();
    let mut output_commitments = Vec::new();
    let mut bond_output_total = 0u64;
    let mut inventory_change_total = 0u64;
    let mut subscription_total = 0u64;
    let mut redemption_remainder_total = 0u64;
    let mut redemption_inventory_return_total = 0u64;

    for opening in &settlement.bond_outputs {
        if opening.amount == 0 {
            return Err(SettlementError::InvalidBondOpening);
        }
        let index = usize::try_from(opening.output_index)
            .map_err(|_| SettlementError::InvalidBondSettlementShape)?;
        if !output_indices.insert(index) {
            return Err(SettlementError::InvalidBondSettlementShape);
        }
        let output = transaction
            .output
            .get(index)
            .ok_or(SettlementError::InvalidBondSettlementShape)?;
        verify_output_commitment(
            output,
            opening.amount,
            opening.asset_blinding_factor,
            opening.value_blinding_factor,
            frozen_asset.asset_id,
        )
        .map_err(|_| SettlementError::InvalidBondOpening)?;

        let mut role_commitment = Vec::with_capacity(97);
        match opening.role {
            BondOutputRoleV2::InventoryVaultChange => {
                if script_sha256(output) != frozen_asset.inventory_vault_script_sha256 {
                    return Err(SettlementError::WrongBondScript);
                }
                inventory_change_total = inventory_change_total
                    .checked_add(opening.amount)
                    .ok_or(SettlementError::BondConservation)?;
                role_commitment.push(0);
            }
            BondOutputRoleV2::Subscription {
                subscription_id,
                recipient_script_sha256,
            } => {
                if subscription_id == [0; 32]
                    || recipient_script_sha256 == [0; 32]
                    || recipient_script_sha256 == frozen_asset.inventory_vault_script_sha256
                    || recipient_script_sha256 == frozen_asset.redemption_queue_script_sha256
                    || script_sha256(output) != recipient_script_sha256
                    || !subscription_ids.insert(subscription_id)
                {
                    return Err(SettlementError::InvalidBondSettlementShape);
                }
                subscription_total = subscription_total
                    .checked_add(opening.amount)
                    .ok_or(SettlementError::BondConservation)?;
                role_commitment.push(1);
                role_commitment.extend_from_slice(&subscription_id);
                role_commitment.extend_from_slice(&recipient_script_sha256);
            }
            BondOutputRoleV2::QueuedRedemptionEntry { .. }
            | BondOutputRoleV2::AuthenticatedQueuedRedemptionRemainder { .. }
            | BondOutputRoleV2::CancelledRedemptionReturn { .. }
            | BondOutputRoleV2::RejectedEnqueueRefund { .. } => {
                return Err(SettlementError::InvalidBondSettlementShape);
            }
            BondOutputRoleV2::QueuedRedemptionRemainder { redemption_id } => {
                if script_sha256(output) != frozen_asset.redemption_queue_script_sha256 {
                    return Err(SettlementError::WrongBondScript);
                }
                let flow = redemptions
                    .get_mut(&redemption_id)
                    .ok_or(SettlementError::BondRedemptionMismatch)?;
                if flow.remainder.replace(opening.amount).is_some() {
                    return Err(SettlementError::BondRedemptionMismatch);
                }
                redemption_remainder_total = redemption_remainder_total
                    .checked_add(opening.amount)
                    .ok_or(SettlementError::BondConservation)?;
                role_commitment.push(2);
                role_commitment.extend_from_slice(&redemption_id);
            }
            BondOutputRoleV2::RedemptionInventoryReturn { redemption_id } => {
                if script_sha256(output) != frozen_asset.inventory_vault_script_sha256 {
                    return Err(SettlementError::WrongBondScript);
                }
                let flow = redemptions
                    .get_mut(&redemption_id)
                    .ok_or(SettlementError::BondRedemptionMismatch)?;
                if flow.inventory_return.replace(opening.amount).is_some() {
                    return Err(SettlementError::BondRedemptionMismatch);
                }
                redemption_inventory_return_total = redemption_inventory_return_total
                    .checked_add(opening.amount)
                    .ok_or(SettlementError::BondConservation)?;
                role_commitment.push(3);
                role_commitment.extend_from_slice(&redemption_id);
            }
        }
        bond_output_total = bond_output_total
            .checked_add(opening.amount)
            .ok_or(SettlementError::BondConservation)?;
        role_commitment.extend_from_slice(&opening.output_index.to_be_bytes());
        role_commitment.extend_from_slice(&opening.amount.to_be_bytes());
        output_commitments.push(sha256_tagged("ECX/bond-output/v2", &role_commitment));
    }

    // No confidential output may escape classification as the frozen bond.
    // Conversely, an explicit output of the frozen asset is forbidden: bond
    // subscriptions, queue remainders, and inventory all stay confidential.
    for (index, output) in transaction.output.iter().enumerate() {
        let confidential = output.asset.is_confidential()
            || output.value.is_confidential()
            || output.nonce.is_confidential();
        if confidential != output_indices.contains(&index) {
            return Err(SettlementError::InvalidBondSettlementShape);
        }
        if output
            .asset
            .explicit()
            .is_some_and(|asset| asset.into_inner().to_byte_array() == frozen_asset.asset_id)
        {
            return Err(SettlementError::InvalidBondOpening);
        }
    }

    let expected_inventory_outputs = inventory_change_total
        .checked_add(subscription_total)
        .ok_or(SettlementError::BondConservation)?;
    if inventory_input_total != expected_inventory_outputs {
        return Err(SettlementError::BondConservation);
    }
    for flow in redemptions.values() {
        let inventory_return = flow
            .inventory_return
            .ok_or(SettlementError::BondRedemptionMismatch)?;
        let remainder = flow.remainder.unwrap_or(0);
        if remainder
            .checked_add(inventory_return)
            .filter(|total| *total == flow.input)
            .is_none()
        {
            return Err(SettlementError::BondRedemptionMismatch);
        }
    }
    if bond_input_total != bond_output_total
        || bond_input_total > FrozenBondAssetV2::FIXED_SUPPLY_ATOMS
    {
        return Err(SettlementError::BondConservation);
    }

    input_commitments.sort_unstable();
    output_commitments.sort_unstable();
    let transaction_id = transaction.txid().to_byte_array();
    let mut settlement_preimage =
        Vec::with_capacity(32 + 32 * (input_commitments.len() + output_commitments.len()));
    settlement_preimage.extend_from_slice(&transaction_id);
    settlement_preimage.extend_from_slice(&input_commitments.concat());
    settlement_preimage.extend_from_slice(&output_commitments.concat());
    let subscription_count = u32::try_from(subscription_ids.len())
        .map_err(|_| SettlementError::InvalidBondSettlementShape)?;
    let redemption_count = u32::try_from(redemptions.len())
        .map_err(|_| SettlementError::InvalidBondSettlementShape)?;

    Ok(VerifiedBondSettlementV2 {
        transaction_id,
        bond_input_total,
        bond_output_total,
        inventory_input_total,
        inventory_change_total,
        subscription_total,
        queued_redemption_input_total,
        redemption_remainder_total,
        redemption_inventory_return_total,
        subscription_count,
        redemption_count,
        settlement_root: sha256_tagged("ECX/bond-settlement/v2", &settlement_preimage),
    })
}

/// Verify one confidential deposit and derive the only `DepositRequest` that
/// the private transition may credit for the corresponding node event.
pub fn verify_confidential_deposit(
    event: &DepositEventV1,
    opening: &ConfidentialDepositOpeningV1,
    expected_usdd_asset_id: Hash32,
    expected_vault_script_sha256: Hash32,
) -> Result<DepositRequest, SettlementError> {
    event.validate()?;
    if opening.version != DEPOSIT_OPENING_VERSION {
        return Err(SettlementError::UnsupportedVersion);
    }
    if opening.transaction.is_empty()
        || opening.transaction.len() > MAX_ELEMENTS_TRANSACTION_BYTES
        || opening.amount == 0
        || expected_usdd_asset_id == [0; 32]
        || expected_vault_script_sha256 == [0; 32]
    {
        return Err(SettlementError::InvalidTransaction);
    }

    let transaction: Transaction = encode::deserialize(&opening.transaction)
        .map_err(|_| SettlementError::InvalidTransaction)?;
    if encode::serialize(&transaction) != opening.transaction
        || transaction.txid().to_byte_array() != event.source_txid
    {
        return Err(SettlementError::InvalidTransaction);
    }
    let output_index =
        usize::try_from(event.deposit_vout).map_err(|_| SettlementError::EventMismatch)?;
    let output = transaction
        .output
        .get(output_index)
        .ok_or(SettlementError::EventMismatch)?;
    if output_sha256(output) != event.output_sha256 {
        return Err(SettlementError::EventMismatch);
    }
    verify_marker(&transaction, event)?;

    let script_hash: [u8; 32] = Sha256::digest(output.script_pubkey.as_bytes()).into();
    if script_hash != expected_vault_script_sha256 {
        return Err(SettlementError::WrongVaultScript);
    }
    verify_opening(output, opening, expected_usdd_asset_id)?;

    let request = DepositRequest {
        version: DepositRequest::VERSION,
        chain_id: event.chain_id,
        deposit_txid: event.source_txid,
        deposit_vout: event.deposit_vout,
        usdd_asset_id: expected_usdd_asset_id,
        trader: event.trader,
        amount: opening.amount,
        observed_height: event.observed_sidechain_height,
    };
    request.validate()?;
    Ok(request)
}

pub fn output_sha256(output: &TxOut) -> Hash32 {
    sha256::Hash::hash(&encode::serialize(output)).to_byte_array()
}

fn decode_transaction(bytes: &[u8]) -> Result<Transaction, SettlementError> {
    if bytes.is_empty() || bytes.len() > MAX_ELEMENTS_TRANSACTION_BYTES {
        return Err(SettlementError::InvalidTransaction);
    }
    let transaction: Transaction =
        encode::deserialize(bytes).map_err(|_| SettlementError::InvalidTransaction)?;
    if encode::serialize(&transaction) != bytes {
        return Err(SettlementError::InvalidTransaction);
    }
    Ok(transaction)
}

/// Bond-inbox admission has its own frozen source-transaction cap. Do not
/// raise the ordinary 400,000-byte settlement limit merely because a source
/// transaction may carry one bounded encrypted bundle in its input-zero
/// Taproot annex. Up to eight distinct source transactions may be aggregated
/// by the per-block inbox rule.
fn decode_bond_inbox_source_transaction_v2(bytes: &[u8]) -> Result<Transaction, SettlementError> {
    if bytes.is_empty() || bytes.len() > MAX_BOND_INBOX_SOURCE_TRANSACTION_BYTES_V2 as usize {
        return Err(SettlementError::InvalidTransaction);
    }
    let transaction: Transaction =
        encode::deserialize(bytes).map_err(|_| SettlementError::InvalidTransaction)?;
    if encode::serialize(&transaction) != bytes {
        return Err(SettlementError::InvalidTransaction);
    }
    Ok(transaction)
}

fn script_sha256(output: &TxOut) -> Hash32 {
    Sha256::digest(output.script_pubkey.as_bytes()).into()
}

fn is_provably_unspendable_script(script: &[u8]) -> bool {
    script.first() == Some(&opcodes::all::OP_RETURN.into_u8())
}

fn explicit_output_amount(output: &TxOut, expected_asset_id: Hash32) -> Option<u64> {
    if output.asset.explicit()?.into_inner().to_byte_array() != expected_asset_id {
        return None;
    }
    output.value.explicit()
}

fn require_explicit_output(
    output: &TxOut,
    expected_asset_id: Hash32,
    expected_amount: u64,
    expected_script_sha256: Hash32,
) -> Result<(), ()> {
    if explicit_output_amount(output, expected_asset_id) != Some(expected_amount)
        || output.nonce != Nonce::Null
        || script_sha256(output) != expected_script_sha256
    {
        return Err(());
    }
    Ok(())
}

fn sha256_tagged(tag: &str, bytes: &[u8]) -> Hash32 {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Enforce the V2 privacy floor on every proof-opened protected asset leg.
///
/// Commitment correctness alone permits a producer to choose zero or reuse a
/// blinding factor. Both make otherwise confidential outputs linkable and can
/// enable small-domain dictionary tests. V1 verification deliberately does
/// not call this helper; V2 is a fresh singleton and program identity.
fn validate_v2_blinding_factors<I>(openings: I) -> Result<(), SettlementError>
where
    I: IntoIterator<Item = ([u8; 32], [u8; 32])>,
{
    use std::collections::BTreeSet;

    let mut all_factors = BTreeSet::new();
    for (asset_factor, value_factor) in openings {
        if asset_factor == [0; 32]
            || value_factor == [0; 32]
            || asset_factor == value_factor
            || !all_factors.insert(asset_factor)
            || !all_factors.insert(value_factor)
        {
            return Err(SettlementError::UnsafeBlindingFactorsV2);
        }
    }
    Ok(())
}

fn verify_output_commitment(
    output: &TxOut,
    amount: u64,
    asset_blinding_factor: [u8; 32],
    value_blinding_factor: [u8; 32],
    expected_usdd_asset_id: Hash32,
) -> Result<(), SettlementError> {
    let opening = ConfidentialDepositOpeningV1 {
        version: DEPOSIT_OPENING_VERSION,
        transaction: Vec::new(),
        amount,
        asset_blinding_factor,
        value_blinding_factor,
    };
    verify_opening(output, &opening, expected_usdd_asset_id)
}

fn verify_marker(transaction: &Transaction, event: &DepositEventV1) -> Result<(), SettlementError> {
    let marker_index =
        usize::try_from(event.marker_vout).map_err(|_| SettlementError::MarkerMismatch)?;
    let marker_output = transaction
        .output
        .get(marker_index)
        .ok_or(SettlementError::MarkerMismatch)?;
    let mut instructions = marker_output.script_pubkey.instructions_minimal();
    if instructions.next() != Some(Ok(Instruction::Op(opcodes::all::OP_RETURN))) {
        return Err(SettlementError::MarkerMismatch);
    }
    let payload = match instructions.next() {
        Some(Ok(Instruction::PushBytes(bytes))) => bytes,
        _ => return Err(SettlementError::MarkerMismatch),
    };
    if instructions.next().is_some() {
        return Err(SettlementError::MarkerMismatch);
    }
    let marker = DepositMarkerV1::decode_payload(payload)?;
    if marker.chain_id != event.chain_id
        || marker.deposit_vout != event.deposit_vout
        || marker.trader != event.trader
    {
        return Err(SettlementError::MarkerMismatch);
    }
    Ok(())
}

fn verify_opening(
    output: &TxOut,
    opening: &ConfidentialDepositOpeningV1,
    expected_usdd_asset_id: Hash32,
) -> Result<(), SettlementError> {
    let secp = Secp256k1::new();
    let asset_id = AssetId::from_byte_array(expected_usdd_asset_id);
    let asset_blinding_factor = AssetBlindingFactor::from_slice(&opening.asset_blinding_factor)
        .map_err(|_| SettlementError::InvalidConfidentialOpening)?;
    let value_blinding_factor = ValueBlindingFactor::from_slice(&opening.value_blinding_factor)
        .map_err(|_| SettlementError::InvalidConfidentialOpening)?;
    let expected_asset = Asset::new_confidential(&secp, asset_id, asset_blinding_factor);
    let asset_generator = expected_asset
        .commitment()
        .ok_or(SettlementError::InvalidConfidentialOpening)?;
    let expected_value = Value::new_confidential(
        &secp,
        opening.amount,
        asset_generator,
        value_blinding_factor,
    );
    if output.asset != expected_asset
        || output.value != expected_value
        || !matches!(output.nonce, Nonce::Confidential(_))
    {
        return Err(SettlementError::InvalidConfidentialOpening);
    }
    let commitment = output
        .value
        .commitment()
        .ok_or(SettlementError::InvalidConfidentialOpening)?;
    let rangeproof = output
        .witness
        .rangeproof
        .as_ref()
        .ok_or(SettlementError::InvalidConfidentialOpening)?;
    let range = rangeproof
        .verify(
            &secp,
            commitment,
            output.script_pubkey.as_bytes(),
            asset_generator,
        )
        .map_err(|_| SettlementError::InvalidConfidentialOpening)?;
    if opening.amount < range.start || opening.amount >= range.end {
        return Err(SettlementError::InvalidConfidentialOpening);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn withdrawal_bundle_envelope_binds_exact_m6id_and_checkpoint() {
        let envelope = WithdrawalBundleEnvelopeV1 {
            version: WITHDRAWAL_BUNDLE_ENVELOPE_VERSION,
            checkpoint_height: 42,
            checkpoint_block_hash: [0x51; 32],
            m6_no_witness: vec![0x61; 300],
        };
        let script = envelope.coinbase_script().unwrap();
        assert_eq!(script[0], opcodes::all::OP_RETURN.into_u8());
        assert_eq!(script[1], opcodes::all::OP_PUSHDATA2.into_u8());
        envelope
            .verify_coinbase_script(&script, envelope.m6id())
            .unwrap();
        let mut wrong_script = script.clone();
        *wrong_script.last_mut().unwrap() ^= 1;
        assert_eq!(
            envelope.verify_coinbase_script(&wrong_script, envelope.m6id()),
            Err(SettlementError::InvalidWithdrawalBundleEnvelope)
        );
        assert_eq!(
            envelope.verify_coinbase_script(&script, [7; 32]),
            Err(SettlementError::InvalidWithdrawalBundleEnvelope)
        );
    }
    use ecx_protocol_core::{
        availability::AvailabilityConfigV1,
        bond_inbox_availability_bundle_root_v2, bond_inbox_custody_receipt_binding_digest_v2,
        bond_inbox_redemption_staging_descriptor_commitment_v2,
        bond_inbox_source_witness_sha256_v2, canonical_bond_inbox_custody_receipts_v2,
        canonical_successor_bond_inbox_custody_receipts_v2,
        oracle::{HybridOracleConfigV1, PPM_DENOMINATOR},
        risk::RiskParams,
        successor_bond_inbox_availability_bundle_root_v2,
        successor_bond_inbox_custody_receipt_binding_digest_v2, truthcoin_anchor_history_root,
        BondInboxMarkerV2, CentralMatcherConfigV1, DepositInboxStateV1, FrozenConfigurationV1,
        Signature64, SuccessorBondInboxMarkerV2, TruthcoinAnchorStateV1, TruthcoinAnchorUpdateV1,
        UsddCheckpointConfigV1, UsddCheckpointUpdateV1, UsddEthereumCheckpointV1, XOnlyKey,
        AVAILABILITY_CUSTODIAN_COUNT, AVAILABILITY_RECOVERY_THRESHOLD, BOND_FIXED_SUPPLY_ATOMS,
        BOND_INBOX_INCLUSION_BLOCKS_V2, BOND_INBOX_MARKER_VERSION,
        BOND_INBOX_MAX_CONSUMED_ENTRIES_PER_TRANSITION_V2,
        BOND_INBOX_MAX_ENTRIES_PER_SIDECHAIN_BLOCK_V2,
        BOND_INBOX_MAX_PENDING_ENTRIES_PER_TRANSITION_V2,
        BOND_INBOX_MAX_UNIQUE_SOURCE_TRANSACTION_BYTES_PER_SIDECHAIN_BLOCK_V2,
        BOND_INBOX_MAX_UNIQUE_SOURCE_WITNESS_BYTES_PER_SIDECHAIN_BLOCK_V2,
        BOND_INBOX_REDEMPTION_STAGING_TAPLEAF_VERSION_V2,
        BOND_INBOX_REFUND_MINIMUM_PARENT_BLOCKS_V2, BOND_REDEMPTION_DELAY_PARENT_BLOCKS,
        BOND_REDEMPTION_MAX_QUEUE_ENTRIES_V2, MATCHER_EXECUTION_INCLUSION_PARENT_BLOCKS_V2,
        MAX_AVAILABILITY_WITNESS_BYTES, MAX_BOND_INBOX_BUNDLE_BYTES_V2, MAX_TRANSITION_ACTIONS,
        RECURSIVE_PROOF_MARKER_BYTES_V2, SUCCESSOR_BOND_INBOX_MARKER_VERSION_V2,
        USDD_MAX_CHECKPOINT_AGE_SECONDS,
    };
    use elements::confidential::AssetBlindingFactor;
    use elements::secp256k1_zkp::{PublicKey, SecretKey};
    use elements::{OutPoint, Script, TxIn, TxOutSecrets, Txid};
    use rand::thread_rng;

    const VALID_TRADER_XONLY: [u8; 32] = [
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
        0x17, 0x98,
    ];

    #[test]
    fn explicit_or_uncommitted_output_is_rejected() {
        let chain_id = [1; 32];
        let inbox = DepositInboxStateV1::genesis([2; 32], chain_id).unwrap();
        let asset_id = AssetId::from_byte_array([3; 32]);
        let marker = DepositMarkerV1 {
            chain_id,
            deposit_vout: 0,
            trader: XOnlyKey(VALID_TRADER_XONLY),
        };
        let marker_script = marker_script(marker.payload_bytes().unwrap());
        let output = TxOut {
            asset: Asset::Explicit(asset_id),
            value: Value::Explicit(100),
            nonce: Nonce::Null,
            script_pubkey: Script::from(vec![0x51]),
            witness: Default::default(),
        };
        let transaction = minimal_transaction(output.clone(), marker_script);
        let event = event_for(&transaction, &output, inbox.head_root, marker.trader);
        let opening = ConfidentialDepositOpeningV1 {
            version: 1,
            transaction: encode::serialize(&transaction),
            amount: 100,
            asset_blinding_factor: [1; 32],
            value_blinding_factor: [2; 32],
        };
        assert_eq!(
            verify_confidential_deposit(
                &event,
                &opening,
                asset_id.into_inner().to_byte_array(),
                Sha256::digest(output.script_pubkey.as_bytes()).into(),
            ),
            Err(SettlementError::InvalidConfidentialOpening)
        );
    }

    #[test]
    fn confidential_opening_derives_exact_deposit() {
        let mut rng = thread_rng();
        let secp = Secp256k1::new();
        let chain_id = [1; 32];
        let inbox = DepositInboxStateV1::genesis([2; 32], chain_id).unwrap();
        let asset_id = AssetId::from_byte_array([3; 32]);
        let trader = XOnlyKey(VALID_TRADER_XONLY);
        let mut vault_script_bytes = vec![0x51, 0x20];
        vault_script_bytes.extend_from_slice(&[7; 32]);
        let vault_script = Script::from(vault_script_bytes);
        let abf = AssetBlindingFactor::from_slice(&[1; 32]).unwrap();
        let vbf = ValueBlindingFactor::from_slice(&[2; 32]).unwrap();
        let receiver_secret = SecretKey::new(&mut rng);
        let receiver_public = PublicKey::from_secret_key(&secp, &receiver_secret);
        let ephemeral_secret = SecretKey::new(&mut rng);
        let secrets = TxOutSecrets::new(asset_id, abf, 100, vbf);
        let input_secrets = TxOutSecrets::new(
            asset_id,
            AssetBlindingFactor::zero(),
            100,
            ValueBlindingFactor::zero(),
        );
        let output = TxOut::with_txout_secrets(
            &mut rng,
            &secp,
            vault_script.clone(),
            receiver_public,
            ephemeral_secret,
            secrets,
            &[input_secrets],
        )
        .unwrap();
        let marker = DepositMarkerV1 {
            chain_id,
            deposit_vout: 0,
            trader,
        };
        let transaction = minimal_transaction(
            output.clone(),
            marker_script(marker.payload_bytes().unwrap()),
        );
        let event = event_for(&transaction, &output, inbox.head_root, trader);
        let opening = ConfidentialDepositOpeningV1 {
            version: 1,
            transaction: encode::serialize(&transaction),
            amount: 100,
            asset_blinding_factor: [1; 32],
            value_blinding_factor: [2; 32],
        };
        let request = verify_confidential_deposit(
            &event,
            &opening,
            asset_id.into_inner().to_byte_array(),
            Sha256::digest(vault_script.as_bytes()).into(),
        )
        .unwrap();
        assert_eq!(request.amount, 100);
        assert_eq!(request.trader, trader);
    }

    #[test]
    fn transition_collateral_input_with_asset_issuance_is_rejected() {
        let (mut settlement, asset_id, vault_script_hash) = valid_transition_settlement();
        let mut transaction = decode_transaction(&settlement.transaction).unwrap();
        transaction.input[2].asset_issuance.amount = Value::Explicit(1);
        settlement.transaction = encode::serialize(&transaction);

        assert_eq!(
            verify_transition_settlement(&settlement, &[], asset_id, vault_script_hash),
            Err(SettlementError::InvalidSettlementShape)
        );
    }

    #[test]
    fn transition_collateral_input_with_pegin_flag_is_rejected() {
        let (mut settlement, asset_id, vault_script_hash) = valid_transition_settlement();
        let mut transaction = decode_transaction(&settlement.transaction).unwrap();
        transaction.input[2].is_pegin = true;
        settlement.transaction = encode::serialize(&transaction);

        assert_eq!(
            verify_transition_settlement(&settlement, &[], asset_id, vault_script_hash),
            Err(SettlementError::InvalidSettlementShape)
        );
    }

    #[test]
    fn bond_v2_deployment_derives_asset_and_destroys_reissuance_token() {
        let fixture = valid_frozen_bond_deployment_v2();
        let verified =
            verify_frozen_bond_deployment_v2(&fixture.deployment, &fixture.frozen_asset).unwrap();

        assert_eq!(verified.bond_asset_id, fixture.frozen_asset.asset_id);
        assert_eq!(
            verified.reissuance_token_asset_id,
            fixture.reissuance_token_asset_id
        );
        assert_eq!(verified.fixed_supply_atoms, BOND_FIXED_SUPPLY_ATOMS_V2);
        assert_eq!(verified.inventory_output_index, 0);
        assert_eq!(verified.reissuance_token_burn_output_index, 1);
        assert_ne!(verified.deployment_commitment, [0; 32]);
    }

    #[test]
    fn bond_inbox_staging_p2tr_renderer_is_exact_and_descriptor_bound() {
        let fixture = bond_inbox_source_transaction_fixture_v2();
        let mut configuration = fixture.configuration;
        let renderer_input = BondInboxRedemptionStagingRendererInputV2 {
            chain_id: fixture.entry.marker.chain_id,
            configuration_hash: fixture.entry.marker.configuration_hash,
            marker_signer: fixture.entry.marker.signer,
            stable_intent_id: fixture.entry.marker.staging_intent_id,
            staging_vout: fixture.entry.marker.staging_vout,
            refund_script_sha256: fixture.entry.marker.refund_script_sha256,
            refund_not_before_parent_height: fixture.entry.marker.refund_not_before_parent_height,
        };
        let rendered =
            bond_inbox_redemption_staging_render_v2(&configuration, renderer_input).unwrap();
        let script = rendered.script_pubkey;
        assert_eq!(script.len(), 34);
        assert_eq!(script.as_bytes()[0], opcodes::all::OP_PUSHNUM_1.into_u8());
        assert_eq!(script.as_bytes()[1], 32);
        let expected_script_sha256: Hash32 = Sha256::digest(script.as_bytes()).into();
        assert_eq!(
            bond_inbox_redemption_staging_script_sha256_v2(&configuration, renderer_input).unwrap(),
            expected_script_sha256
        );
        assert_eq!(
            rendered.lower_branch_hash,
            tapbranch_elements_raw_bytes_v2(
                TapNodeHash::from_byte_array(rendered.refund_leaf_hash),
                TapNodeHash::from_byte_array(rendered.hidden_node_hash),
            )
            .to_byte_array()
        );
        assert_eq!(
            rendered.top_branch_hash,
            tapbranch_elements_raw_bytes_v2(
                TapNodeHash::from_byte_array(rendered.process_leaf_hash),
                TapNodeHash::from_byte_array(rendered.lower_branch_hash),
            )
            .to_byte_array()
        );

        let mut mutations = Vec::new();
        let mut value = renderer_input;
        value.chain_id[0] ^= 1;
        mutations.push(value);
        let mut value = renderer_input;
        value.configuration_hash[0] ^= 1;
        mutations.push(value);
        let other_secret = SecretKey::from_slice(&[53; 32]).unwrap();
        let other_keypair =
            elements::secp256k1_zkp::Keypair::from_secret_key(&Secp256k1::new(), &other_secret);
        let mut value = renderer_input;
        value.marker_signer = XOnlyKey(
            elements::secp256k1_zkp::XOnlyPublicKey::from_keypair(&other_keypair)
                .0
                .serialize(),
        );
        mutations.push(value);
        let mut value = renderer_input;
        value.stable_intent_id[0] ^= 1;
        mutations.push(value);
        let mut value = renderer_input;
        value.staging_vout += 1;
        mutations.push(value);
        let mut value = renderer_input;
        value.refund_script_sha256[0] ^= 1;
        mutations.push(value);
        let mut value = renderer_input;
        value.refund_not_before_parent_height += 1;
        mutations.push(value);
        for mutation in mutations {
            if mutation.chain_id != configuration.base.chain_id
                || mutation.configuration_hash != configuration.digest()
            {
                assert!(bond_inbox_redemption_staging_render_v2(&configuration, mutation).is_err());
            } else {
                assert_ne!(
                    bond_inbox_redemption_staging_render_v2(&configuration, mutation)
                        .unwrap()
                        .script_pubkey,
                    script
                );
            }
        }

        // The topology is semantic, even though every individual TapBranch
        // internally sorts its child hashes. Neither grouping both spendable
        // leaves together nor treating the hidden raw node as a spendable leaf
        // may reproduce the V18 root/script.
        let process = TapNodeHash::from_byte_array(rendered.process_leaf_hash);
        let refund = TapNodeHash::from_byte_array(rendered.refund_leaf_hash);
        let hidden = TapNodeHash::from_byte_array(rendered.hidden_node_hash);
        let spendable_pair = tapbranch_elements_raw_bytes_v2(process, refund);
        let wrong_grouping = tapbranch_elements_raw_bytes_v2(spendable_pair, hidden);
        assert_ne!(wrong_grouping.to_byte_array(), rendered.top_branch_hash);
        let leaf_version =
            LeafVersion::from_u8(configuration.bond_inbox_redemption_staging_tapleaf_version)
                .unwrap();
        let hidden_as_leaf = TapNodeHash::from_byte_array(
            TapLeafHash::from_script(
                &elements::Script::from(rendered.hidden_node_hash.to_vec()),
                leaf_version,
            )
            .to_byte_array(),
        );
        let wrong_lower = tapbranch_elements_raw_bytes_v2(refund, hidden_as_leaf);
        let wrong_hidden_leaf_root = tapbranch_elements_raw_bytes_v2(process, wrong_lower);
        assert_ne!(
            wrong_hidden_leaf_root.to_byte_array(),
            rendered.top_branch_hash
        );

        // A substituted role CMR cannot reuse the frozen descriptor identity.
        configuration.bond_inbox_redemption_staging_process_cmr[0] ^= 1;
        assert!(bond_inbox_redemption_staging_script_v2(&configuration, renderer_input).is_err());
    }

    #[test]
    fn v18_staging_renderer_vector_is_byte_exact() {
        let fixture = bond_inbox_source_transaction_fixture_v2();
        let configuration = fixture.configuration;
        let input = BondInboxRedemptionStagingRendererInputV2 {
            chain_id: fixture.entry.marker.chain_id,
            configuration_hash: fixture.entry.marker.configuration_hash,
            marker_signer: fixture.entry.marker.signer,
            stable_intent_id: fixture.entry.marker.staging_intent_id,
            staging_vout: fixture.entry.marker.staging_vout,
            refund_script_sha256: fixture.entry.marker.refund_script_sha256,
            refund_not_before_parent_height: fixture.entry.marker.refund_not_before_parent_height,
        };
        let rendered = bond_inbox_redemption_staging_render_v2(&configuration, input).unwrap();
        let vector = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"),
            "/../../Testing/v18-staging-renderer-vector.txt"))
            .expect("required preserved V18 staging renderer fixture is missing");
        let expected = |name: &str| {
            vector
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{name}=")))
                .unwrap_or_else(|| panic!("missing V18 vector field {name}"))
        };
        assert_eq!(
            expected("ECX_V18_CONFIGURATION_HASH"),
            hex::encode(configuration.digest())
        );
        assert_eq!(expected("ECX_V18_CHAIN_ID"), hex::encode(input.chain_id));
        assert_eq!(
            expected("ECX_V18_MARKER_SIGNER"),
            hex::encode(input.marker_signer.0)
        );
        assert_eq!(
            expected("ECX_V18_STABLE_INTENT_ID"),
            hex::encode(input.stable_intent_id)
        );
        assert_eq!(
            expected("ECX_V18_STAGING_VOUT"),
            input.staging_vout.to_string()
        );
        assert_eq!(
            expected("ECX_V18_REFUND_SCRIPT_SHA256"),
            hex::encode(input.refund_script_sha256)
        );
        assert_eq!(
            expected("ECX_V18_REFUND_NOT_BEFORE_PARENT_HEIGHT"),
            input.refund_not_before_parent_height.to_string()
        );
        assert_eq!(
            expected("ECX_V18_STAGING_NUMS_INTERNAL_KEY"),
            hex::encode(configuration.bond_inbox_redemption_staging_internal_key)
        );
        assert_eq!(
            expected("ECX_V18_STAGING_TAPLEAF_VERSION"),
            format!(
                "{:02x}",
                configuration.bond_inbox_redemption_staging_tapleaf_version
            )
        );
        assert_eq!(
            expected("ECX_V18_STAGING_PROCESS_CMR"),
            hex::encode(configuration.bond_inbox_redemption_staging_process_cmr)
        );
        assert_eq!(
            expected("ECX_V18_STAGING_REFUND_CMR"),
            hex::encode(configuration.bond_inbox_redemption_staging_refund_cmr)
        );
        assert_eq!(
            expected("ECX_V18_STAGING_TEMPLATE_COMMITMENT"),
            hex::encode(configuration.bond_inbox_redemption_staging_template_commitment)
        );
        assert_eq!(
            expected("ECX_V18_STAGING_RENDERER_DOMAIN"),
            hex::encode(configuration.bond_inbox_redemption_staging_renderer_domain)
        );
        assert_eq!(
            expected("ECX_V18_STAGING_HIDDEN_NODE"),
            hex::encode(rendered.hidden_node_hash)
        );
        assert_eq!(
            expected("ECX_V18_STAGING_PROCESS_LEAF"),
            hex::encode(rendered.process_leaf_hash)
        );
        assert_eq!(
            expected("ECX_V18_STAGING_REFUND_LEAF"),
            hex::encode(rendered.refund_leaf_hash)
        );
        assert_eq!(
            expected("ECX_V18_STAGING_LOWER_BRANCH"),
            hex::encode(rendered.lower_branch_hash)
        );
        assert_eq!(
            expected("ECX_V18_STAGING_TOP_BRANCH"),
            hex::encode(rendered.top_branch_hash)
        );
        assert_eq!(
            expected("ECX_V18_STAGING_SCRIPT"),
            hex::encode(rendered.script_pubkey.as_bytes())
        );
        assert_eq!(
            expected("ECX_V18_STAGING_SCRIPT_SHA256"),
            hex::encode(Sha256::digest(rendered.script_pubkey.as_bytes()))
        );
    }

    #[test]
    fn source_staging_requires_both_proofs_even_with_recommitted_witness() {
        let fixture = bond_inbox_source_transaction_fixture_v2();
        for remove_rangeproof in [false, true] {
            let mut transaction = decode_bond_inbox_source_transaction_v2(&fixture.source_transaction).unwrap();
            let staging = &mut transaction.output[fixture.entry.marker.staging_vout as usize];
            assert!(staging.witness.rangeproof.is_some());
            assert!(staging.witness.surjection_proof.is_some());
            if remove_rangeproof { staging.witness.rangeproof = None; }
            else { staging.witness.surjection_proof = None; }
            // Helper recomputes wtxid and exact witness commitment, so this
            // cannot pass merely by rejecting the old transaction digest.
            assert_source_fixture_rejected_v2(&fixture, transaction);
        }
        let fixture = successor_bond_inbox_source_transaction_fixture_v2();
        for remove_rangeproof in [false, true] {
            let mut transaction = decode_bond_inbox_source_transaction_v2(&fixture.source_transaction).unwrap();
            let staging = &mut transaction.output[fixture.entry.marker.staging_vout as usize];
            assert!(staging.witness.rangeproof.is_some());
            assert!(staging.witness.surjection_proof.is_some());
            if remove_rangeproof { staging.witness.rangeproof = None; }
            else { staging.witness.surjection_proof = None; }
            assert_successor_source_fixture_rejected_v2(&fixture, transaction);
        }
    }

    #[test]
    fn bond_inbox_source_transaction_binds_native_framing_marker_and_staging() {
        let fixture = bond_inbox_source_transaction_fixture_v2();
        let annex = bond_inbox_source_annex_v2(&fixture.bundle, &fixture.receipts).unwrap();
        let (decoded_bundle, decoded_receipts) = decode_bond_inbox_source_annex_v2(&annex).unwrap();
        assert_eq!(decoded_bundle, fixture.bundle);
        assert_eq!(decoded_receipts, fixture.receipts);
        let verified = verify_bond_inbox_source_transaction_v2(
            &fixture.entry,
            &fixture.source_transaction,
            &fixture.bundle,
            &fixture.receipts,
            &fixture.configuration,
        )
        .unwrap();
        assert_eq!(verified.txid, fixture.entry.source_txid);
        assert_eq!(verified.wtxid, fixture.entry.source_wtxid);
        assert_eq!(
            verified.staging_vout,
            Some(fixture.entry.marker.staging_vout)
        );
        assert_eq!(
            verified.staging_script_sha256,
            Some(
                bond_inbox_redemption_staging_script_sha256_v2(
                    &fixture.configuration,
                    BondInboxRedemptionStagingRendererInputV2 {
                        chain_id: fixture.entry.marker.chain_id,
                        configuration_hash: fixture.entry.marker.configuration_hash,
                        marker_signer: fixture.entry.marker.signer,
                        stable_intent_id: fixture.entry.marker.staging_intent_id,
                        staging_vout: fixture.entry.marker.staging_vout,
                        refund_script_sha256: fixture.entry.marker.refund_script_sha256,
                        refund_not_before_parent_height: fixture
                            .entry
                            .marker
                            .refund_not_before_parent_height,
                    },
                )
                .unwrap(),
            )
        );

        let mut wrong_txid = fixture.entry;
        wrong_txid.source_txid[0] ^= 1;
        assert_eq!(
            verify_bond_inbox_source_transaction_v2(
                &wrong_txid,
                &fixture.source_transaction,
                &fixture.bundle,
                &fixture.receipts,
                &fixture.configuration,
            ),
            Err(SettlementError::BondInboxSourceMismatch)
        );
        let mut wrong_wtxid = fixture.entry;
        wrong_wtxid.source_wtxid[0] ^= 1;
        assert_eq!(
            verify_bond_inbox_source_transaction_v2(
                &wrong_wtxid,
                &fixture.source_transaction,
                &fixture.bundle,
                &fixture.receipts,
                &fixture.configuration,
            ),
            Err(SettlementError::BondInboxSourceMismatch)
        );

        let mut transaction =
            decode_bond_inbox_source_transaction_v2(&fixture.source_transaction).unwrap();
        transaction.input[0].witness.script_witness.swap(0, 1);
        assert_source_fixture_rejected_v2(&fixture, transaction);

        let mut transaction =
            decode_bond_inbox_source_transaction_v2(&fixture.source_transaction).unwrap();
        transaction.input[0]
            .witness
            .script_witness
            .push(annex.clone());
        assert_source_fixture_rejected_v2(&fixture, transaction);

        let mut malformed_annex = annex.clone();
        malformed_annex[10..14].copy_from_slice(&1u32.to_be_bytes());
        assert!(decode_bond_inbox_source_annex_v2(&malformed_annex).is_err());
        let mut trailing_annex = annex.clone();
        trailing_annex.push(0);
        assert!(decode_bond_inbox_source_annex_v2(&trailing_annex).is_err());

        let mut transaction =
            decode_bond_inbox_source_transaction_v2(&fixture.source_transaction).unwrap();
        let mut second_input = transition_input(61);
        second_input.witness.script_witness = vec![vec![0x51; 64], annex.clone()];
        transaction.input.push(second_input);
        assert_source_fixture_rejected_v2(&fixture, transaction);

        let mut transaction =
            decode_bond_inbox_source_transaction_v2(&fixture.source_transaction).unwrap();
        transaction.output[usize::try_from(fixture.entry.marker_vout).unwrap()].script_pubkey =
            Script::from(vec![opcodes::all::OP_RETURN.into_u8()]);
        assert_source_fixture_rejected_v2(&fixture, transaction);

        let mut transaction =
            decode_bond_inbox_source_transaction_v2(&fixture.source_transaction).unwrap();
        transaction.output[usize::try_from(fixture.entry.marker.staging_vout).unwrap()]
            .script_pubkey = Script::from(vec![0x51]);
        assert_source_fixture_rejected_v2(&fixture, transaction);

        let mut transaction =
            decode_bond_inbox_source_transaction_v2(&fixture.source_transaction).unwrap();
        transaction.output[usize::try_from(fixture.entry.marker_vout).unwrap()].asset =
            Asset::Explicit(AssetId::from_byte_array([0x91; 32]));
        assert_source_fixture_rejected_v2(&fixture, transaction);

        let mut transaction =
            decode_bond_inbox_source_transaction_v2(&fixture.source_transaction).unwrap();
        transaction.input[0].is_pegin = true;
        assert_source_fixture_rejected_v2(&fixture, transaction);

        let mut transaction =
            decode_bond_inbox_source_transaction_v2(&fixture.source_transaction).unwrap();
        transaction.input[0].asset_issuance.amount = Value::Explicit(1);
        assert_source_fixture_rejected_v2(&fixture, transaction);

        let mut transaction =
            decode_bond_inbox_source_transaction_v2(&fixture.source_transaction).unwrap();
        transaction
            .output
            .push(transaction.output[usize::try_from(fixture.entry.marker_vout).unwrap()].clone());
        assert_source_fixture_rejected_v2(&fixture, transaction);

        let mut substituted_configuration = fixture.configuration.clone();
        substituted_configuration.bond_inbox_redemption_staging_refund_cmr[0] ^= 1;
        assert!(verify_bond_inbox_source_transaction_v2(
            &fixture.entry,
            &fixture.source_transaction,
            &fixture.bundle,
            &fixture.receipts,
            &substituted_configuration,
        )
        .is_err());

        let mut trailing = fixture.source_transaction.clone();
        trailing.push(0);
        assert!(verify_bond_inbox_source_transaction_v2(
            &fixture.entry,
            &trailing,
            &fixture.bundle,
            &fixture.receipts,
            &fixture.configuration,
        )
        .is_err());
    }

    #[test]
    fn successor_bond_inbox_source_transaction_binds_u128_entry_and_fresh_domains() {
        let fixture = successor_bond_inbox_source_transaction_fixture_v2();
        if std::env::var_os("ECX_DUMP_SUCCESSOR_NODE_SOURCE_VECTOR").is_some() {
            println!(
                "configuration_hash={}",
                hex::encode(fixture.configuration.digest())
            );
            println!(
                "chain_id={}",
                hex::encode(fixture.configuration.base.chain_id)
            );
            println!(
                "policy_asset_id={}",
                hex::encode(fixture.configuration.base.policy_asset_id)
            );
            println!(
                "bond_asset_id={}",
                hex::encode(fixture.configuration.bond_asset_id)
            );
            println!(
                "staging_internal_key={}",
                hex::encode(
                    fixture
                        .configuration
                        .bond_inbox_redemption_staging_internal_key
                )
            );
            println!(
                "staging_process_cmr={}",
                hex::encode(
                    fixture
                        .configuration
                        .bond_inbox_redemption_staging_process_cmr
                )
            );
            println!(
                "staging_refund_cmr={}",
                hex::encode(
                    fixture
                        .configuration
                        .bond_inbox_redemption_staging_refund_cmr
                )
            );
            println!(
                "availability_scheme_hash={}",
                hex::encode(fixture.configuration.base.availability.scheme_hash)
            );
            println!(
                "availability_registry_hash={}",
                hex::encode(
                    fixture
                        .configuration
                        .base
                        .availability
                        .custodian_registry_hash
                )
            );
            for custodian in &fixture.custodian_public {
                println!(
                    "custodian_{}_encryption={}",
                    custodian.index,
                    hex::encode(custodian.encryption_public_key)
                );
                println!(
                    "custodian_{}_attestation={}",
                    custodian.index,
                    hex::encode(custodian.attestation_public_key)
                );
            }
            println!("source_txid={}", hex::encode(fixture.entry.source_txid));
            println!("source_wtxid={}", hex::encode(fixture.entry.source_wtxid));
            println!(
                "source_transaction_len={}",
                fixture.entry.source_transaction_len
            );
            println!(
                "source_transaction_sha256={}",
                hex::encode(Sha256::digest(&fixture.source_transaction))
            );
            println!(
                "source_witness_sha256={}",
                hex::encode(fixture.entry.source_witness_sha256)
            );
            println!("source_witness_len={}", fixture.entry.source_witness_len);
            println!("marker_vout={}", fixture.entry.marker_vout);
            println!(
                "observed_sidechain_height={}",
                fixture.entry.observed_sidechain_height
            );
            println!(
                "observed_parent_height={}",
                fixture.entry.observed_parent_height
            );
            println!(
                "source_transaction={}",
                hex::encode(&fixture.source_transaction)
            );
        }
        assert!(fixture.entry.index > u128::from(u64::MAX));
        let original_entry_hash = fixture.entry.entry_hash();
        let verified = verify_successor_bond_inbox_source_transaction_v2(
            &fixture.entry,
            &fixture.source_transaction,
            &fixture.bundle,
            &fixture.receipts,
            &fixture.configuration,
        )
        .unwrap();
        assert_eq!(verified.txid, fixture.entry.source_txid);
        assert_eq!(verified.wtxid, fixture.entry.source_wtxid);
        assert_eq!(verified.staging_vout, Some(0));

        // The node-assigned lifetime index is deliberately not precommitted by
        // the wallet transaction. Reassignment changes the authenticated inbox
        // entry/root while preserving exact source-transaction validity.
        let mut reassigned = fixture.entry;
        reassigned.index += 1;
        assert_ne!(reassigned.entry_hash(), original_entry_hash);
        verify_successor_bond_inbox_source_transaction_v2(
            &reassigned,
            &fixture.source_transaction,
            &fixture.bundle,
            &fixture.receipts,
            &fixture.configuration,
        )
        .unwrap();

        let successor_payload = fixture
            .entry
            .marker
            .payload_bytes(MAX_BOND_INBOX_BUNDLE_BYTES_V2)
            .unwrap();
        assert_eq!(
            successor_payload.len(),
            ecx_protocol_core::BOND_INBOX_MARKER_LEN
        );
        let mut historical_version = successor_payload;
        historical_version[4] = BOND_INBOX_MARKER_VERSION;
        assert!(SuccessorBondInboxMarkerV2::decode_payload(
            &historical_version,
            MAX_BOND_INBOX_BUNDLE_BYTES_V2,
        )
        .is_err());

        let mut wrong_witness = fixture.entry;
        wrong_witness.source_witness_sha256[0] ^= 1;
        assert_eq!(
            verify_successor_bond_inbox_source_transaction_v2(
                &wrong_witness,
                &fixture.source_transaction,
                &fixture.bundle,
                &fixture.receipts,
                &fixture.configuration,
            ),
            Err(SettlementError::Protocol(ProtocolError::InvalidBondInbox))
        );

        let mut wrong_bundle = fixture.bundle.clone();
        wrong_bundle[0] ^= 1;
        assert_eq!(
            verify_successor_bond_inbox_source_transaction_v2(
                &fixture.entry,
                &fixture.source_transaction,
                &wrong_bundle,
                &fixture.receipts,
                &fixture.configuration,
            ),
            Err(SettlementError::BondInboxSourceMismatch)
        );

        let mut transaction =
            decode_bond_inbox_source_transaction_v2(&fixture.source_transaction).unwrap();
        transaction.output[usize::try_from(fixture.entry.marker.staging_vout).unwrap()]
            .script_pubkey = Script::from(vec![0x51]);
        assert_successor_source_fixture_rejected_v2(&fixture, transaction);

        let mut transaction =
            decode_bond_inbox_source_transaction_v2(&fixture.source_transaction).unwrap();
        transaction.input[0].witness.script_witness[1].push(0);
        assert_successor_source_fixture_rejected_v2(&fixture, transaction);
    }

    #[test]
    fn frozen_successor_node_vector_round_trips_real_crypto_and_elementsregtest_asset() {
        let exact_vector = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"),
            "/../../Testing/successor-bond-inbox-node-vector-v23.json"))
            .expect("required preserved successor node fixture is missing");
        let vector: serde_json::Value = serde_json::from_str(&exact_vector)
        .unwrap();
        assert_eq!(
            vector["schema"].as_str(),
            Some("ECX_SUCCESSOR_BOND_INBOX_NODE_VECTOR_V1")
        );
        assert_eq!(vector["network"].as_str(), Some("elementsregtest"));
        assert_eq!(
            vector["proof_profile"].as_str(),
            Some("incremental-successor")
        );

        let decode32 = |value: &serde_json::Value| -> [u8; 32] {
            hex::decode(value.as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        };
        let source_transaction =
            hex::decode(vector["source_transaction_hex"].as_str().unwrap()).unwrap();
        assert_eq!(
            source_transaction.len(),
            usize::try_from(vector["entry"]["source_transaction_len"].as_u64().unwrap()).unwrap()
        );
        assert_eq!(
            Sha256::digest(&source_transaction).as_slice(),
            decode32(&vector["entry"]["source_transaction_sha256"])
        );

        let mut configuration = bond_inbox_source_test_configuration_v2();
        configuration.base.policy_asset_id = decode32(&vector["policy_asset_id"]);
        configuration.base.availability.custodian_registry_hash =
            decode32(&vector["availability"]["registry_hash"]);
        configuration.validate().unwrap();
        assert_eq!(
            configuration.digest(),
            decode32(&vector["configuration_hash"])
        );
        assert_eq!(
            configuration.base.policy_asset_id,
            AssetId::from_str("b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23")
                .unwrap()
                .into_inner()
                .to_byte_array()
        );

        let transaction = decode_bond_inbox_source_transaction_v2(&source_transaction).unwrap();
        assert_eq!(
            transaction.txid().to_byte_array(),
            decode32(&vector["entry"]["source_txid"])
        );
        assert_eq!(
            transaction.wtxid().to_byte_array(),
            decode32(&vector["entry"]["source_wtxid"])
        );
        let annex = transaction.input[0].witness.script_witness.last().unwrap();
        let (bundle, receipts) = decode_bond_inbox_source_annex_v2(annex).unwrap();
        let marker_script = transaction.output[1].script_pubkey.as_bytes();
        assert_eq!(marker_script[0], opcodes::all::OP_RETURN.into_u8());
        assert_eq!(marker_script[1], opcodes::all::OP_PUSHDATA2.into_u8());
        let marker = SuccessorBondInboxMarkerV2::decode_payload(
            &marker_script[4..],
            MAX_BOND_INBOX_BUNDLE_BYTES_V2,
        )
        .unwrap();
        let witness = elements_transaction_witness_bytes_v2(&source_transaction).unwrap();
        let entry = SuccessorBondInboxEntryV2 {
            version: SuccessorBondInboxEntryV2::VERSION,
            index: (u128::from(u64::MAX) + 1) << 32,
            previous_root: [81; 32],
            observed_sidechain_height: 10,
            observed_parent_height: 1_000,
            source_block_hash: [82; 32],
            source_txid: transaction.txid().to_byte_array(),
            source_wtxid: transaction.wtxid().to_byte_array(),
            source_transaction_len: u32::try_from(source_transaction.len()).unwrap(),
            source_witness_sha256: Sha256::digest(&witness).into(),
            source_witness_len: u32::try_from(witness.len()).unwrap(),
            source_tx_index: 0,
            marker_vout: 1,
            marker,
        };
        assert_eq!(
            entry.source_witness_sha256,
            decode32(&vector["entry"]["source_witness_sha256"])
        );
        assert_eq!(
            u64::from(entry.source_witness_len),
            vector["entry"]["source_witness_len"].as_u64().unwrap()
        );
        verify_successor_bond_inbox_source_transaction_v2(
            &entry,
            &source_transaction,
            &bundle,
            &receipts,
            &configuration,
        )
        .unwrap();
    }

    #[test]
    fn bond_v2_deployment_rejects_zero_blinding_factors() {
        let fixture = valid_frozen_bond_deployment_v2();

        let mut zero_asset = fixture.deployment.clone();
        zero_asset.inventory_asset_blinding_factor = [0; 32];
        assert_eq!(
            verify_frozen_bond_deployment_v2(&zero_asset, &fixture.frozen_asset),
            Err(SettlementError::UnsafeBlindingFactorsV2)
        );

        let mut zero_value = fixture.deployment.clone();
        zero_value.inventory_value_blinding_factor = [0; 32];
        assert_eq!(
            verify_frozen_bond_deployment_v2(&zero_value, &fixture.frozen_asset),
            Err(SettlementError::UnsafeBlindingFactorsV2)
        );
    }

    #[test]
    fn bond_v2_deployment_rejects_wrong_supply_and_reissuance_form() {
        let fixture = valid_frozen_bond_deployment_v2();

        let mut wrong_supply = fixture.deployment.clone();
        let mut wrong_supply_transaction = decode_transaction(&wrong_supply.transaction).unwrap();
        wrong_supply_transaction.input[0].asset_issuance.amount =
            Value::Explicit(BOND_FIXED_SUPPLY_ATOMS_V2 - 1);
        wrong_supply.transaction = encode::serialize(&wrong_supply_transaction);
        assert_eq!(
            verify_frozen_bond_deployment_v2(&wrong_supply, &fixture.frozen_asset),
            Err(SettlementError::InvalidBondDeployment)
        );

        let mut reissuance = fixture.deployment.clone();
        let mut reissuance_transaction = decode_transaction(&reissuance.transaction).unwrap();
        reissuance_transaction.input[0]
            .asset_issuance
            .asset_blinding_nonce = elements::secp256k1_zkp::Tweak::from_slice(&[3; 32]).unwrap();
        reissuance.transaction = encode::serialize(&reissuance_transaction);
        assert_eq!(
            verify_frozen_bond_deployment_v2(&reissuance, &fixture.frozen_asset),
            Err(SettlementError::InvalidBondDeployment)
        );
    }

    #[test]
    fn bond_v2_deployment_requires_provably_unspendable_token_output() {
        let mut fixture = valid_frozen_bond_deployment_v2();
        let spendable_script = Script::from(vec![opcodes::all::OP_PUSHNUM_1.into_u8()]);
        let mut transaction = decode_transaction(&fixture.deployment.transaction).unwrap();
        transaction.output[1].script_pubkey = spendable_script.clone();
        fixture.deployment.transaction = encode::serialize(&transaction);
        fixture.frozen_asset.reissuance_token_burn_script_sha256 =
            Sha256::digest(spendable_script.as_bytes()).into();

        assert_eq!(
            verify_frozen_bond_deployment_v2(&fixture.deployment, &fixture.frozen_asset),
            Err(SettlementError::BondReissuanceTokenNotDestroyed)
        );
    }

    #[test]
    fn bond_v2_deployment_rejects_extra_bond_or_token_outputs() {
        let fixture = valid_frozen_bond_deployment_v2();

        let mut extra_bond = fixture.deployment.clone();
        let mut extra_bond_transaction = decode_transaction(&extra_bond.transaction).unwrap();
        extra_bond_transaction.output.push(explicit_output(
            fixture.frozen_asset.asset_id,
            1,
            Script::from(vec![opcodes::all::OP_RETURN.into_u8()]),
        ));
        extra_bond.transaction = encode::serialize(&extra_bond_transaction);
        assert_eq!(
            verify_frozen_bond_deployment_v2(&extra_bond, &fixture.frozen_asset),
            Err(SettlementError::InvalidBondDeployment)
        );

        let mut extra_token = fixture.deployment.clone();
        let mut extra_token_transaction = decode_transaction(&extra_token.transaction).unwrap();
        extra_token_transaction.output.push(explicit_output(
            fixture.reissuance_token_asset_id,
            1,
            Script::from(vec![opcodes::all::OP_RETURN.into_u8()]),
        ));
        extra_token.transaction = encode::serialize(&extra_token_transaction);
        assert_eq!(
            verify_frozen_bond_deployment_v2(&extra_token, &fixture.frozen_asset),
            Err(SettlementError::BondReissuanceTokenNotDestroyed)
        );
    }

    #[test]
    fn bond_v2_conserves_subscriptions_and_partial_redemptions() {
        let fixture = valid_bond_settlement_v2();
        let verified =
            verify_bond_settlement_v2(&fixture.settlement, &fixture.frozen_asset).unwrap();

        assert_eq!(FrozenBondAssetV2::DECIMALS, 8);
        assert_eq!(FrozenBondAssetV2::FIXED_SUPPLY_ATOMS, 2_100_000_000_000_000);
        assert_eq!(verified.bond_input_total, 100);
        assert_eq!(verified.bond_output_total, 100);
        assert_eq!(verified.inventory_input_total, 70);
        assert_eq!(verified.inventory_change_total, 40);
        assert_eq!(verified.subscription_total, 30);
        assert_eq!(verified.queued_redemption_input_total, 30);
        assert_eq!(verified.redemption_remainder_total, 10);
        assert_eq!(verified.redemption_inventory_return_total, 20);
        assert_eq!(verified.subscription_count, 1);
        assert_eq!(verified.redemption_count, 1);
        assert_ne!(verified.settlement_root, [0; 32]);
    }

    #[test]
    fn bond_v2_rejects_zero_and_repeated_blinding_factors() {
        let fixture = valid_bond_settlement_v2();

        let mut zero = fixture.settlement.clone();
        zero.bond_outputs[0].value_blinding_factor = [0; 32];
        assert_eq!(
            verify_bond_settlement_v2(&zero, &fixture.frozen_asset),
            Err(SettlementError::UnsafeBlindingFactorsV2)
        );

        let mut repeated_asset = fixture.settlement.clone();
        repeated_asset.bond_outputs[1].asset_blinding_factor =
            repeated_asset.bond_outputs[0].asset_blinding_factor;
        assert_eq!(
            verify_bond_settlement_v2(&repeated_asset, &fixture.frozen_asset),
            Err(SettlementError::UnsafeBlindingFactorsV2)
        );

        let mut repeated_value = fixture.settlement.clone();
        repeated_value.bond_outputs[1].value_blinding_factor =
            repeated_value.bond_outputs[0].value_blinding_factor;
        assert_eq!(
            verify_bond_settlement_v2(&repeated_value, &fixture.frozen_asset),
            Err(SettlementError::UnsafeBlindingFactorsV2)
        );
    }

    #[test]
    fn bond_v2_rejects_fresh_issuance_and_reissuance() {
        let fixture = valid_bond_settlement_v2();

        let mut issued = fixture.settlement.clone();
        let mut issued_transaction = decode_transaction(&issued.transaction).unwrap();
        issued_transaction.input[0].asset_issuance.amount = Value::Explicit(1);
        issued.transaction = encode::serialize(&issued_transaction);
        assert_eq!(
            verify_bond_settlement_v2(&issued, &fixture.frozen_asset),
            Err(SettlementError::BondIssuanceForbidden)
        );

        let mut reissued = fixture.settlement.clone();
        let mut reissued_transaction = decode_transaction(&reissued.transaction).unwrap();
        reissued_transaction.input[0]
            .asset_issuance
            .asset_blinding_nonce = elements::secp256k1_zkp::Tweak::from_slice(&[1; 32]).unwrap();
        reissued_transaction.input[0].asset_issuance.asset_entropy = [2; 32];
        reissued_transaction.input[0].asset_issuance.amount = Value::Explicit(1);
        reissued.transaction = encode::serialize(&reissued_transaction);
        assert_eq!(
            verify_bond_settlement_v2(&reissued, &fixture.frozen_asset),
            Err(SettlementError::BondIssuanceForbidden)
        );
    }

    #[test]
    fn bond_v2_rejects_counterfeit_asset_commitment() {
        let mut fixture = valid_bond_settlement_v2();
        let mut transaction = decode_transaction(&fixture.settlement.transaction).unwrap();
        transaction.output[1] =
            confidential_test_output([99; 32], 30, 5, 6, fixture.subscription_script.clone());
        fixture.settlement.transaction = encode::serialize(&transaction);

        assert_eq!(
            verify_bond_settlement_v2(&fixture.settlement, &fixture.frozen_asset),
            Err(SettlementError::InvalidBondOpening)
        );
    }

    #[test]
    fn bond_v2_rejects_inventory_inflation() {
        let mut fixture = valid_bond_settlement_v2();
        let mut transaction = decode_transaction(&fixture.settlement.transaction).unwrap();
        transaction.output[1] = confidential_test_output(
            fixture.frozen_asset.asset_id,
            31,
            5,
            6,
            fixture.subscription_script.clone(),
        );
        fixture.settlement.bond_outputs[1].amount = 31;
        fixture.settlement.transaction = encode::serialize(&transaction);

        assert_eq!(
            verify_bond_settlement_v2(&fixture.settlement, &fixture.frozen_asset),
            Err(SettlementError::BondConservation)
        );
    }

    #[test]
    fn bond_v2_rejects_redemption_without_inventory_return() {
        let mut fixture = valid_bond_settlement_v2();
        let mut transaction = decode_transaction(&fixture.settlement.transaction).unwrap();
        transaction.output.remove(3);
        fixture.settlement.transaction = encode::serialize(&transaction);
        fixture.settlement.bond_outputs.remove(3);

        assert_eq!(
            verify_bond_settlement_v2(&fixture.settlement, &fixture.frozen_asset),
            Err(SettlementError::BondRedemptionMismatch)
        );
    }

    #[test]
    fn bond_v2_rejects_unclassified_confidential_output() {
        let mut fixture = valid_bond_settlement_v2();
        let mut transaction = decode_transaction(&fixture.settlement.transaction).unwrap();
        transaction.output.push(confidential_test_output(
            [77; 32],
            1,
            13,
            14,
            Script::from(vec![0x51, 0x77]),
        ));
        fixture.settlement.transaction = encode::serialize(&transaction);

        assert_eq!(
            verify_bond_settlement_v2(&fixture.settlement, &fixture.frozen_asset),
            Err(SettlementError::InvalidBondSettlementShape)
        );
    }

    #[test]
    fn bond_v2_rejects_wrong_inventory_script_and_explicit_bond_output() {
        let fixture = valid_bond_settlement_v2();

        let mut wrong_script = fixture.settlement.clone();
        let mut wrong_script_transaction = decode_transaction(&wrong_script.transaction).unwrap();
        wrong_script_transaction.output[0] = confidential_test_output(
            fixture.frozen_asset.asset_id,
            40,
            3,
            4,
            fixture.subscription_script.clone(),
        );
        wrong_script.transaction = encode::serialize(&wrong_script_transaction);
        assert_eq!(
            verify_bond_settlement_v2(&wrong_script, &fixture.frozen_asset),
            Err(SettlementError::WrongBondScript)
        );

        let mut explicit_bond = fixture.settlement.clone();
        let mut explicit_bond_transaction = decode_transaction(&explicit_bond.transaction).unwrap();
        explicit_bond_transaction.output.push(explicit_output(
            fixture.frozen_asset.asset_id,
            1,
            Script::from(vec![0x51]),
        ));
        explicit_bond.transaction = encode::serialize(&explicit_bond_transaction);
        assert_eq!(
            verify_bond_settlement_v2(&explicit_bond, &fixture.frozen_asset),
            Err(SettlementError::InvalidBondOpening)
        );
    }

    #[test]
    fn transition_v2_atomically_settles_usdd_subscription_and_redemption() {
        let fixture = valid_transition_settlement_v2();
        let verified = verify_transition_settlement_v2(
            &fixture.settlement,
            &[],
            &fixture.actions,
            fixture.usdd_asset_id,
            fixture.collateral_vault_script_sha256,
            fixture.insurance_reserve_script_sha256,
            &fixture.frozen_bond_asset,
        )
        .unwrap();

        assert_eq!(verified.collateral_input_total, 150);
        assert_eq!(verified.collateral_output_total, 150);
        assert_eq!(verified.collateral_vault_input_total, 100);
        assert_eq!(verified.insurance_reserve_input_total, 50);
        assert_eq!(verified.collateral_vault_change_total, 60);
        assert_eq!(verified.insurance_reserve_output_total, 75);
        assert_eq!(verified.subscription_contribution_total, 20);
        assert_eq!(verified.redemption_payment_total, 15);
        assert_eq!(verified.bond_input_total, 130);
        assert_eq!(verified.bond_output_total, 130);
        assert_eq!(verified.bond_inventory_input_total, 100);
        assert_eq!(verified.bond_inventory_change_total, 80);
        assert_eq!(verified.bond_subscription_total, 20);
        assert_eq!(verified.queued_redemption_input_total, 30);
        assert_eq!(verified.redemption_remainder_total, 10);
        assert_eq!(verified.redemption_inventory_return_total, 20);
        assert_ne!(
            verified.collateral_settlement_root,
            verified.bond_settlement_root
        );
        assert_ne!(verified.combined_settlement_root, [0; 32]);
    }

    #[test]
    fn transition_v2_reserve_supports_zero_to_positive_creation() {
        let verified = verify_reserve_aggregate_flow_v2(
            &[(CollateralInputRoleV2::CollateralVault, 50)],
            &[(CollateralOutputRoleV2::InsuranceReserveChange, 50)],
        );

        assert_eq!(verified.collateral_vault_input_total, 50);
        assert_eq!(verified.insurance_reserve_input_total, 0);
        assert_eq!(verified.collateral_vault_change_total, 0);
        assert_eq!(verified.insurance_reserve_output_total, 50);
    }

    #[test]
    fn transition_v2_reserve_supports_positive_to_zero_destruction() {
        let verified = verify_reserve_aggregate_flow_v2(
            &[(CollateralInputRoleV2::InsuranceReserve, 50)],
            &[(CollateralOutputRoleV2::CollateralVaultChange, 50)],
        );

        assert_eq!(verified.collateral_vault_input_total, 0);
        assert_eq!(verified.insurance_reserve_input_total, 50);
        assert_eq!(verified.collateral_vault_change_total, 50);
        assert_eq!(verified.insurance_reserve_output_total, 0);
    }

    #[test]
    fn transition_v2_reserve_supports_fragmented_many_to_many_successors() {
        let verified = verify_reserve_aggregate_flow_v2(
            &[
                (CollateralInputRoleV2::InsuranceReserve, 20),
                (CollateralInputRoleV2::InsuranceReserve, 30),
            ],
            &[
                (CollateralOutputRoleV2::InsuranceReserveChange, 10),
                (CollateralOutputRoleV2::InsuranceReserveChange, 15),
                (CollateralOutputRoleV2::InsuranceReserveChange, 25),
            ],
        );

        assert_eq!(verified.insurance_reserve_input_total, 50);
        assert_eq!(verified.insurance_reserve_output_total, 50);
        assert_eq!(verified.collateral_input_total, 50);
        assert_eq!(verified.collateral_output_total, 50);
    }

    #[test]
    fn transition_v2_rejects_zero_and_repeated_blinding_factors_across_assets() {
        let fixture = valid_transition_settlement_v2();
        let verify = |settlement: &TransitionSettlementV2| {
            verify_transition_settlement_v2(
                settlement,
                &[],
                &fixture.actions,
                fixture.usdd_asset_id,
                fixture.collateral_vault_script_sha256,
                fixture.insurance_reserve_script_sha256,
                &fixture.frozen_bond_asset,
            )
        };

        let mut zero = fixture.settlement.clone();
        zero.collateral_outputs[0].asset_blinding_factor = [0; 32];
        assert_eq!(verify(&zero), Err(SettlementError::UnsafeBlindingFactorsV2));

        let mut repeated_asset = fixture.settlement.clone();
        repeated_asset.bond_outputs[0].asset_blinding_factor =
            repeated_asset.collateral_outputs[0].asset_blinding_factor;
        assert_eq!(
            verify(&repeated_asset),
            Err(SettlementError::UnsafeBlindingFactorsV2)
        );

        let mut repeated_value = fixture.settlement.clone();
        repeated_value.bond_outputs[0].value_blinding_factor =
            repeated_value.collateral_outputs[0].value_blinding_factor;
        assert_eq!(
            verify(&repeated_value),
            Err(SettlementError::UnsafeBlindingFactorsV2)
        );
    }

    #[test]
    fn transition_v2_rejects_unpaired_subscription_and_redemption_ids() {
        let fixture = valid_transition_settlement_v2();

        let mut subscription = fixture.settlement.clone();
        subscription.bond_outputs[1].role = BondOutputRoleV2::Subscription {
            subscription_id: [99; 32],
            recipient_script_sha256: fixture.subscription_recipient_script_sha256,
        };
        assert_eq!(
            verify_transition_settlement_v2(
                &subscription,
                &[],
                &fixture.actions,
                fixture.usdd_asset_id,
                fixture.collateral_vault_script_sha256,
                fixture.insurance_reserve_script_sha256,
                &fixture.frozen_bond_asset,
            ),
            Err(SettlementError::BondActionMismatch)
        );

        let mut redemption = fixture.settlement.clone();
        redemption.collateral_outputs[3].role = CollateralOutputRoleV2::BondRedemptionPayment {
            redemption_id: [98; 32],
            recipient_script_sha256: fixture.redemption_recipient_script_sha256,
        };
        assert_eq!(
            verify_transition_settlement_v2(
                &redemption,
                &[],
                &fixture.actions,
                fixture.usdd_asset_id,
                fixture.collateral_vault_script_sha256,
                fixture.insurance_reserve_script_sha256,
                &fixture.frozen_bond_asset,
            ),
            Err(SettlementError::BondActionMismatch)
        );
    }

    #[test]
    fn transition_v2_rejects_unclassified_output_and_issuance() {
        let fixture = valid_transition_settlement_v2();

        let mut extra = fixture.settlement.clone();
        let mut extra_transaction = decode_transaction(&extra.transaction).unwrap();
        extra_transaction.output.push(confidential_test_output(
            [100; 32],
            1,
            29,
            30,
            Script::from(vec![0x51, 0x66]),
        ));
        extra.transaction = encode::serialize(&extra_transaction);
        assert_eq!(
            verify_transition_settlement_v2(
                &extra,
                &[],
                &fixture.actions,
                fixture.usdd_asset_id,
                fixture.collateral_vault_script_sha256,
                fixture.insurance_reserve_script_sha256,
                &fixture.frozen_bond_asset,
            ),
            Err(SettlementError::InvalidSettlementShapeV2)
        );

        let mut issuance = fixture.settlement.clone();
        let mut issuance_transaction = decode_transaction(&issuance.transaction).unwrap();
        issuance_transaction.input[4].asset_issuance.amount = Value::Explicit(1);
        issuance.transaction = encode::serialize(&issuance_transaction);
        assert_eq!(
            verify_transition_settlement_v2(
                &issuance,
                &[],
                &fixture.actions,
                fixture.usdd_asset_id,
                fixture.collateral_vault_script_sha256,
                fixture.insurance_reserve_script_sha256,
                &fixture.frozen_bond_asset,
            ),
            Err(SettlementError::BondIssuanceForbidden)
        );
    }

    #[test]
    fn transition_v2_rejects_confidential_usdd_treasury_or_operator_output() {
        let fixture = valid_transition_settlement_v2();
        let mut treasury = fixture.settlement.clone();
        let mut transaction = decode_transaction(&treasury.transaction).unwrap();
        transaction.output.push(confidential_test_output(
            fixture.usdd_asset_id,
            1,
            31,
            32,
            Script::from(vec![0x51, 0x74, 0x72, 0x65, 0x61, 0x73, 0x75, 0x72, 0x79]),
        ));
        treasury.transaction = encode::serialize(&transaction);

        assert_eq!(
            verify_transition_settlement_v2(
                &treasury,
                &[],
                &fixture.actions,
                fixture.usdd_asset_id,
                fixture.collateral_vault_script_sha256,
                fixture.insurance_reserve_script_sha256,
                &fixture.frozen_bond_asset,
            ),
            Err(SettlementError::InvalidSettlementShapeV2)
        );
    }

    #[test]
    fn transition_v2_binds_enqueue_request_and_fifo_covenant() {
        let fixture = redemption_lifecycle_settlement_v2(false);
        verify_transition_settlement_v2(
            &fixture.settlement,
            &[],
            &fixture.actions,
            fixture.usdd_asset_id,
            fixture.collateral_vault_script_sha256,
            fixture.insurance_reserve_script_sha256,
            &fixture.frozen_bond_asset,
        )
        .unwrap();

        let mut wrong_claimant = fixture.actions.clone();
        if let BondSettlementActionV2::EnqueueRedemption { claimant, .. } = &mut wrong_claimant[0] {
            *claimant = [101; 32];
        }
        assert_eq!(
            verify_transition_settlement_v2(
                &fixture.settlement,
                &[],
                &wrong_claimant,
                fixture.usdd_asset_id,
                fixture.collateral_vault_script_sha256,
                fixture.insurance_reserve_script_sha256,
                &fixture.frozen_bond_asset,
            ),
            Err(SettlementError::BondActionMismatch)
        );
    }

    #[test]
    fn transition_v2_accepts_only_exact_authenticated_staging_txout_projection() {
        let fixture = redemption_lifecycle_settlement_v2(false);
        let mut projected = fixture.settlement.clone();
        let previous: Transaction =
            encode::deserialize(&projected.bond_inputs[0].previous_transaction).unwrap();
        let exact_serialized_txout = encode::serialize(&previous.output[0]);
        let exact_serialized_txout_witness = encode::serialize(&previous.output[0].witness);
        projected.bond_inputs[0].previous_transaction.clear();
        let authenticated = AuthenticatedPreviousOutputV2 {
            input_index: projected.bond_inputs[0].input_index,
            previous_txid: previous.txid().to_byte_array(),
            previous_vout: 0,
            exact_serialized_txout: exact_serialized_txout.clone(),
            exact_serialized_txout_witness,
        };
        verify_transition_settlement_v2_with_authenticated_previous_outputs(
            &projected,
            &[],
            &fixture.actions,
            fixture.usdd_asset_id,
            fixture.collateral_vault_script_sha256,
            fixture.insurance_reserve_script_sha256,
            &fixture.frozen_bond_asset,
            std::slice::from_ref(&authenticated),
        )
        .unwrap();

        let mut wrong_txout = authenticated.clone();
        wrong_txout.exact_serialized_txout[0] ^= 1;
        assert!(
            verify_transition_settlement_v2_with_authenticated_previous_outputs(
                &projected,
                &[],
                &fixture.actions,
                fixture.usdd_asset_id,
                fixture.collateral_vault_script_sha256,
                fixture.insurance_reserve_script_sha256,
                &fixture.frozen_bond_asset,
                &[wrong_txout],
            )
            .is_err()
        );

        let mut wrong_outpoint = authenticated;
        wrong_outpoint.previous_txid[0] ^= 1;
        assert!(
            verify_transition_settlement_v2_with_authenticated_previous_outputs(
                &projected,
                &[],
                &fixture.actions,
                fixture.usdd_asset_id,
                fixture.collateral_vault_script_sha256,
                fixture.insurance_reserve_script_sha256,
                &fixture.frozen_bond_asset,
                &[wrong_outpoint],
            )
            .is_err()
        );
    }

    #[test]
    fn transition_v2_accepts_recursive_opened_vault_inventory_and_queue_projections() {
        let fixture = valid_transition_settlement_v2();
        let mut projected = fixture.settlement.clone();
        let mut authenticated = Vec::new();
        for opening in &mut projected.collateral_inputs {
            let verified = verify_previous_transaction_output_openings_v2(
                &opening.previous_transaction,
                &[PreviousTransactionOutputOpeningV2 {
                    previous_vout: opening.previous_vout,
                    expected_asset_id: fixture.usdd_asset_id,
                    amount: opening.amount,
                    asset_blinding_factor: opening.asset_blinding_factor,
                    value_blinding_factor: opening.value_blinding_factor,
                }],
            )
            .unwrap();
            let output = verified.outputs[0];
            authenticated.push(AuthenticatedOpenedPreviousOutputV2 {
                input_index: opening.input_index,
                previous_txid: verified.txid,
                previous_vout: output.previous_vout,
                expected_asset_id: output.expected_asset_id,
                amount: output.amount,
                script_sha256: output.script_sha256,
                txout_sha256: output.txout_sha256,
                txout_witness_sha256: output.txout_witness_sha256,
            });
            opening.previous_transaction.clear();
        }
        for opening in &mut projected.bond_inputs {
            let verified = verify_previous_transaction_output_openings_v2(
                &opening.previous_transaction,
                &[PreviousTransactionOutputOpeningV2 {
                    previous_vout: opening.previous_vout,
                    expected_asset_id: fixture.frozen_bond_asset.asset_id,
                    amount: opening.amount,
                    asset_blinding_factor: opening.asset_blinding_factor,
                    value_blinding_factor: opening.value_blinding_factor,
                }],
            )
            .unwrap();
            let output = verified.outputs[0];
            authenticated.push(AuthenticatedOpenedPreviousOutputV2 {
                input_index: opening.input_index,
                previous_txid: verified.txid,
                previous_vout: output.previous_vout,
                expected_asset_id: output.expected_asset_id,
                amount: output.amount,
                script_sha256: output.script_sha256,
                txout_sha256: output.txout_sha256,
                txout_witness_sha256: output.txout_witness_sha256,
            });
            opening.previous_transaction.clear();
        }
        verify_transition_settlement_v2_with_authenticated_opened_previous_outputs(
            &projected,
            &[],
            &fixture.actions,
            fixture.usdd_asset_id,
            fixture.collateral_vault_script_sha256,
            fixture.insurance_reserve_script_sha256,
            &fixture.frozen_bond_asset,
            &[],
            &authenticated,
        )
        .unwrap();

        authenticated[0].amount += 1;
        assert!(
            verify_transition_settlement_v2_with_authenticated_opened_previous_outputs(
                &projected,
                &[],
                &fixture.actions,
                fixture.usdd_asset_id,
                fixture.collateral_vault_script_sha256,
                fixture.insurance_reserve_script_sha256,
                &fixture.frozen_bond_asset,
                &[],
                &authenticated,
            )
            .is_err()
        );
    }

    #[test]
    fn predecessor_transaction_child_projection_verifies_exact_rangeproof_and_opening() {
        let asset_id = [0x91; 32];
        let output = confidential_test_output(asset_id, 25, 41, 42, Script::from(vec![0x51, 0x91]));
        let transaction = Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![],
            output: vec![output],
        };
        let encoded = encode::serialize(&transaction);
        let opening = PreviousTransactionOutputOpeningV2 {
            previous_vout: 0,
            expected_asset_id: asset_id,
            amount: 25,
            asset_blinding_factor: [41; 32],
            value_blinding_factor: [42; 32],
        };
        let verified =
            verify_previous_transaction_output_openings_v2(&encoded, &[opening]).unwrap();
        assert_eq!(verified.txid, transaction.txid().to_byte_array());
        assert_eq!(verified.outputs[0].amount, 25);
        assert_ne!(verified.outputs[0].txout_witness_sha256, [0; 32]);

        let mut wrong = opening;
        wrong.amount += 1;
        assert!(verify_previous_transaction_output_openings_v2(&encoded, &[wrong]).is_err());
        let mut duplicate = opening;
        duplicate.value_blinding_factor = [43; 32];
        assert!(
            verify_previous_transaction_output_openings_v2(&encoded, &[opening, duplicate])
                .is_err()
        );
    }

    #[test]
    fn transition_v2_binds_stable_cancellation_and_complete_return() {
        let fixture = redemption_lifecycle_settlement_v2(true);
        verify_transition_settlement_v2(
            &fixture.settlement,
            &[],
            &fixture.actions,
            fixture.usdd_asset_id,
            fixture.collateral_vault_script_sha256,
            fixture.insurance_reserve_script_sha256,
            &fixture.frozen_bond_asset,
        )
        .unwrap();

        let mut forged_cancellation = fixture.actions.clone();
        if let BondSettlementActionV2::CancelRedemption {
            cancellation_id, ..
        } = &mut forged_cancellation[0]
        {
            *cancellation_id = [102; 32];
        }
        assert_eq!(
            verify_transition_settlement_v2(
                &fixture.settlement,
                &[],
                &forged_cancellation,
                fixture.usdd_asset_id,
                fixture.collateral_vault_script_sha256,
                fixture.insurance_reserve_script_sha256,
                &fixture.frozen_bond_asset,
            ),
            Err(SettlementError::BondActionMismatch)
        );
    }

    #[test]
    fn truthcoin_rendered_settlement_requires_actual_state_scripts() {
        let mut f = valid_truthcoin_anchor_settlement();
        let check = |f: &TruthcoinAnchorFixture, cmr| {
            truthcoin_authority::rendered_settlement_journal(
                &f.settlement, &f.prior, &f.successor, &f.update, cmr,
                &f.authentication, &f.deployment, f.policy_asset)
        };
        // The old structural fixture has placeholder scripts, and must fail.
        assert!(check(&f, [42;32]).is_err());
        let mut previous = decode_transaction(&f.settlement.prior_authority_transaction).unwrap();
        previous.output[0].script_pubkey = truthcoin_authority::render_authority_script(
            &f.prior, [42;32]).unwrap().script;
        f.settlement.prior_authority_transaction = encode::serialize(&previous);
        f.update.prior_authority_outpoint.txid = previous.txid().to_byte_array();
        f.successor.cumulative_update_root = truthcoin_anchor_history_root(
            &f.prior, &f.successor, &f.update);
        let mut tx = decode_transaction(&f.settlement.transaction).unwrap();
        tx.input[0].previous_output.txid = previous.txid();
        tx.output[0].script_pubkey = truthcoin_authority::render_authority_script(
            &f.successor, [42;32]).unwrap().script;
        f.settlement.transaction = encode::serialize(&tx);
        f.update.successor_transaction_id = tx.txid().to_byte_array();
        let journal = check(&f, [42;32]).unwrap();
        assert_eq!(journal.transaction_id, tx.txid().to_byte_array());
        assert_eq!(journal.next_commitment, f.successor.commitment());
        assert!(check(&f, [43;32]).is_err());
        tx.output[0].script_pubkey = Script::from(vec![0x51]);
        f.settlement.transaction = encode::serialize(&tx);
        f.update.successor_transaction_id = tx.txid().to_byte_array();
        assert!(check(&f, [42;32]).is_err());
    }

    #[test]
    fn truthcoin_authority_renderer_binds_state_and_program() {
        let f = valid_truthcoin_anchor_settlement();
        let render = truthcoin_authority::render_authority_script;
        let old = render(&f.prior, [42;32]).unwrap();
        let next = render(&f.successor, [42;32]).unwrap();
        assert_ne!(old.script, next.script);
        assert_ne!(old.script, render(&f.prior, [43;32]).unwrap().script);
        assert_eq!(old.control_block.len(), 65);
        assert_eq!(&old.control_block[1..33],
            &ecx_protocol_core::truthcoin_authority_policy::KEYLESS_INTERNAL_KEY);
        assert_eq!(&old.control_block[33..], &old.state_node);
        assert!(render(&f.prior, [0;32]).is_err());
        let mut bad = f.prior.clone(); bad.configuration_hash = [0;32];
        assert!(render(&bad, [42;32]).is_err());
    }

    #[test]
    fn truthcoin_journal_derives_raw_transaction_bindings() {
        let f = valid_truthcoin_anchor_settlement();
        let journal = truthcoin_authority::settlement_journal(
            &f.settlement, &f.prior, &f.successor, &f.update, &f.scripts,
            &f.authentication, &f.deployment, f.policy_asset,
        ).unwrap();
        let sponsor = decode_transaction(&f.settlement.sponsor_previous_transaction).unwrap();
        assert_eq!(journal.transaction_id, f.update.successor_transaction_id);
        assert_eq!(journal.prior_commitment, f.prior.commitment());
        assert_eq!(journal.next_commitment, f.successor.commitment());
        assert_eq!(journal.authority.txid, f.update.prior_authority_outpoint.txid);
        assert_eq!(journal.authority.amount, 1);
        assert_eq!(journal.sponsor.txid, sponsor.txid().to_byte_array());
        assert_eq!(journal.sponsor.script_hash, script_sha256(&sponsor.output[0]));
        assert_eq!(journal.sponsor.amount, 1_000);
        assert_eq!(journal.prior_parent_hash, f.successor.bitcoin_checkpoint_hash);
        assert_eq!(journal.prior_parent_chainwork, f.successor.bitcoin_checkpoint_chainwork);
    }

    #[test]
    fn truthcoin_journal_rejects_redirected_sponsor_change() {
        let mut f = valid_truthcoin_anchor_settlement();
        let mut tx = decode_transaction(&f.settlement.transaction).unwrap();
        tx.output[1].script_pubkey = Script::from(vec![0x51, 0x52]);
        // Even updating the descriptor and transaction ID cannot authorize theft.
        f.scripts.sponsor_change_script_sha256 = script_sha256(&tx.output[1]);
        f.update.successor_transaction_id = tx.txid().to_byte_array();
        f.settlement.transaction = encode::serialize(&tx);
        assert!(matches!(truthcoin_authority::settlement_journal(
            &f.settlement, &f.prior, &f.successor, &f.update, &f.scripts,
            &f.authentication, &f.deployment, f.policy_asset,
        ), Err(SettlementError::InvalidTruthcoinSponsor)));
    }

    #[test]
    fn truthcoin_anchor_spend_and_recreate_is_fully_linked() {
        let fixture = valid_truthcoin_anchor_settlement();
        let verified = verify_truthcoin_anchor_settlement(
            &fixture.settlement,
            &fixture.prior,
            &fixture.successor,
            &fixture.update,
            &fixture.scripts,
            &fixture.authentication,
            &fixture.deployment,
            fixture.policy_asset,
        )
        .unwrap();
        assert_eq!(
            verified.transaction_id,
            fixture.update.successor_transaction_id
        );
        assert_eq!(verified.successor_authority_outpoint.vout, 0);
        assert_eq!(verified.sponsor_change_amount, 900);
        assert_eq!(verified.fee_amount, 100);
    }

    #[test]
    fn truthcoin_anchor_rejects_extra_output() {
        let mut fixture = valid_truthcoin_anchor_settlement();
        let mut transaction = decode_transaction(&fixture.settlement.transaction).unwrap();
        transaction.output.push(transaction.output[1].clone());
        fixture.settlement.transaction = encode::serialize(&transaction);
        fixture.update.successor_transaction_id = transaction.txid().to_byte_array();

        assert_eq!(
            verify_truthcoin_anchor_settlement(
                &fixture.settlement,
                &fixture.prior,
                &fixture.successor,
                &fixture.update,
                &fixture.scripts,
                &fixture.authentication,
                &fixture.deployment,
                fixture.policy_asset,
            ),
            Err(SettlementError::InvalidTruthcoinAnchorShape)
        );
    }

    #[test]
    fn truthcoin_anchor_rejects_sponsor_inflation() {
        let mut fixture = valid_truthcoin_anchor_settlement();
        let mut transaction = decode_transaction(&fixture.settlement.transaction).unwrap();
        transaction.output[1].value = Value::Explicit(901);
        fixture.settlement.transaction = encode::serialize(&transaction);
        fixture.update.successor_transaction_id = transaction.txid().to_byte_array();

        assert_eq!(
            verify_truthcoin_anchor_settlement(
                &fixture.settlement,
                &fixture.prior,
                &fixture.successor,
                &fixture.update,
                &fixture.scripts,
                &fixture.authentication,
                &fixture.deployment,
                fixture.policy_asset,
            ),
            Err(SettlementError::InvalidTruthcoinSponsor)
        );
    }

    #[test]
    fn truthcoin_anchor_rejects_state_script_substitution() {
        let mut fixture = valid_truthcoin_anchor_settlement();
        fixture.scripts.successor_state_commitment = [99; 32];
        assert_eq!(
            verify_truthcoin_anchor_settlement(
                &fixture.settlement,
                &fixture.prior,
                &fixture.successor,
                &fixture.update,
                &fixture.scripts,
                &fixture.authentication,
                &fixture.deployment,
                fixture.policy_asset,
            ),
            Err(SettlementError::InvalidTruthcoinAuthority)
        );
    }

    #[test]
    fn truthcoin_anchor_rejects_caller_selected_deployment_policy() {
        let mut fixture = valid_truthcoin_anchor_settlement();
        fixture.deployment.script_tree_configuration_hash = [98; 32];
        assert_eq!(
            verify_truthcoin_anchor_settlement(
                &fixture.settlement,
                &fixture.prior,
                &fixture.successor,
                &fixture.update,
                &fixture.scripts,
                &fixture.authentication,
                &fixture.deployment,
                fixture.policy_asset,
            ),
            Err(SettlementError::InvalidTruthcoinAuthority)
        );
    }

    #[test]
    fn usdd_finalized_ethereum_checkpoint_rolls_through_elements_transaction() {
        let authority_asset = [61; 32];
        let policy_asset = [62; 32];
        let tree_hash = [63; 32];
        let config = UsddCheckpointConfigV1 {
            version: 1,
            ethereum_light_client_configuration_hash: [60; 32],
            authority_configuration_hash: usdd_checkpoint_authority_configuration_hash(
                authority_asset,
                1,
                tree_hash,
                policy_asset,
            ),
            maximum_checkpoint_age_seconds: USDD_MAX_CHECKPOINT_AGE_SECONDS,
        };
        let prior = UsddEthereumCheckpointV1 {
            version: 1,
            configuration_hash: config.digest(),
            sequence: 0,
            light_client_digest: [50; 32],
            finalized_beacon_slot: 1_000,
            finalized_beacon_root: [51; 32],
            finalized_execution_block_hash: [52; 32],
            finalized_execution_state_root: [53; 32],
            finalized_execution_block_number: 2_000,
            finalized_execution_timestamp: 10_000,
            accepted_parent_mtp: 10_060,
            prior_checkpoint_commitment: [0; 32],
            update_proof_commitment: [54; 32],
        };
        let successor = UsddEthereumCheckpointV1 {
            sequence: 1,
            light_client_digest: [55; 32],
            finalized_beacon_slot: 1_032,
            finalized_beacon_root: [56; 32],
            finalized_execution_block_hash: [57; 32],
            finalized_execution_state_root: [58; 32],
            finalized_execution_block_number: 2_020,
            finalized_execution_timestamp: 10_240,
            accepted_parent_mtp: 10_300,
            prior_checkpoint_commitment: prior.commitment(),
            update_proof_commitment: [59; 32],
            ..prior
        };
        let prior_script = state_test_script(prior.commitment());
        let successor_script = state_test_script(successor.commitment());
        let sponsor_script = Script::from(vec![0x51, 0x52]);
        let prior_transaction = Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![],
            output: vec![explicit_output(authority_asset, 1, prior_script.clone())],
        };
        let sponsor_transaction = Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![],
            output: vec![explicit_output(policy_asset, 1_000, sponsor_script.clone())],
        };
        let transaction = Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: OutPoint::new(prior_transaction.txid(), 0),
                    ..TxIn::default()
                },
                TxIn {
                    previous_output: OutPoint::new(sponsor_transaction.txid(), 0),
                    ..TxIn::default()
                },
            ],
            output: vec![
                explicit_output(authority_asset, 1, successor_script.clone()),
                explicit_output(policy_asset, 900, sponsor_script.clone()),
                explicit_output(policy_asset, 100, Script::new()),
            ],
        };
        let update = UsddCheckpointUpdateV1 {
            version: 1,
            prior_authority_outpoint: AnchorOutpointV1 {
                txid: prior_transaction.txid().to_byte_array(),
                vout: 0,
            },
            successor_transaction_id: transaction.txid().to_byte_array(),
            successor_authority_output_index: 0,
        };
        let scripts = UsddCheckpointAuthorityScriptsV1 {
            prior_state_commitment: prior.commitment(),
            prior_script_sha256: Sha256::digest(prior_script.as_bytes()).into(),
            successor_state_commitment: successor.commitment(),
            successor_script_sha256: Sha256::digest(successor_script.as_bytes()).into(),
            sponsor_change_script_sha256: Sha256::digest(sponsor_script.as_bytes()).into(),
        };
        let settlement = UsddCheckpointSettlementV1 {
            version: 1,
            transaction: encode::serialize(&transaction),
            prior_authority_transaction: encode::serialize(&prior_transaction),
            sponsor_previous_transaction: encode::serialize(&sponsor_transaction),
            sponsor_previous_vout: 0,
        };
        let verified = verify_usdd_checkpoint_settlement(
            &settlement,
            &prior,
            &successor,
            &update,
            &scripts,
            &config,
            authority_asset,
            1,
            tree_hash,
            policy_asset,
            successor.accepted_parent_mtp,
        )
        .unwrap();
        assert_eq!(verified.successor_authority_outpoint.vout, 0);
        assert_eq!(verified.fee_amount, 100);

        // Rebind the transaction ID and caller-supplied script descriptor too:
        // neither may authorize redirecting the sponsor's change. The native
        // authority leaf compares input_script_hash(1) with output_script_hash(1).
        let mut redirected_transaction = transaction.clone();
        redirected_transaction.output[1].script_pubkey = Script::from(vec![0x53]);
        let redirected_settlement = UsddCheckpointSettlementV1 {
            transaction: encode::serialize(&redirected_transaction),
            ..settlement.clone()
        };
        let redirected_update = UsddCheckpointUpdateV1 {
            successor_transaction_id: redirected_transaction.txid().to_byte_array(),
            ..update
        };
        let redirected_scripts = UsddCheckpointAuthorityScriptsV1 {
            sponsor_change_script_sha256: script_sha256(&redirected_transaction.output[1]),
            ..scripts
        };
        assert_eq!(
            verify_usdd_checkpoint_settlement(
                &redirected_settlement, &prior, &successor, &redirected_update,
                &redirected_scripts, &config, authority_asset, 1, tree_hash,
                policy_asset, successor.accepted_parent_mtp,
            ),
            Err(SettlementError::InvalidTruthcoinSponsor)
        );

        let mut substituted = config;
        substituted.authority_configuration_hash[0] ^= 1;
        assert_eq!(
            verify_usdd_checkpoint_settlement(
                &settlement,
                &prior,
                &successor,
                &update,
                &scripts,
                &substituted,
                authority_asset,
                1,
                tree_hash,
                policy_asset,
                successor.accepted_parent_mtp,
            ),
            Err(SettlementError::InvalidUsddCheckpointAuthority)
        );

        assert_eq!(
            verify_usdd_checkpoint_settlement(
                &settlement,
                &prior,
                &successor,
                &update,
                &scripts,
                &config,
                authority_asset,
                1,
                tree_hash,
                policy_asset,
                successor.accepted_parent_mtp + 1,
            ),
            Err(SettlementError::UsddCheckpointContext)
        );
    }

    struct TruthcoinAnchorFixture {
        settlement: TruthcoinAnchorSettlementV1,
        prior: TruthcoinAnchorStateV1,
        successor: TruthcoinAnchorStateV1,
        update: TruthcoinAnchorUpdateV1,
        scripts: TruthcoinAnchorAuthorityScriptsV1,
        authentication: TruthcoinAuthenticationConfigV1,
        deployment: TruthcoinAnchorDeploymentV1,
        policy_asset: Hash32,
    }

    fn valid_truthcoin_anchor_settlement() -> TruthcoinAnchorFixture {
        let authority_asset = [31; 32];
        let policy_asset = [32; 32];
        let authentication = truthcoin_anchor_authentication();
        let deployment = TruthcoinAnchorDeploymentV1 {
            version: TruthcoinAnchorDeploymentV1::VERSION,
            authority_asset_id: authority_asset,
            authority_amount: 1,
            script_tree_configuration_hash: [34; 32],
        };
        let configuration_hash =
            truthcoin_anchor_configuration_hash(&authentication, &deployment, policy_asset);
        let prior = truthcoin_anchor_state(0, configuration_hash);
        let prior_script = state_test_script(prior.commitment());
        let prior_transaction = Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![],
            output: vec![explicit_output(authority_asset, 1, prior_script.clone())],
        };
        let sponsor_script = Script::from(vec![0x51, 0x51]);
        let sponsor_transaction = Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![],
            output: vec![explicit_output(policy_asset, 1_000, sponsor_script.clone())],
        };
        let mut update = TruthcoinAnchorUpdateV1 {
            version: TruthcoinAnchorUpdateV1::VERSION,
            prior_authority_outpoint: AnchorOutpointV1 {
                txid: prior_transaction.txid().to_byte_array(),
                vout: 0,
            },
            // This field is deliberately excluded from the state/history hash,
            // avoiding a transaction-id/state-script circular commitment.
            successor_transaction_id: [1; 32],
            successor_authority_output_index: 0,
            update_public_values_hash: [33; 32],
        };
        let mut successor = truthcoin_anchor_state(1, configuration_hash);
        successor.last_update_proof_commitment = update.update_public_values_hash;
        successor.cumulative_update_root =
            truthcoin_anchor_history_root(&prior, &successor, &update);
        let successor_script = state_test_script(successor.commitment());
        let transaction = Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: OutPoint::new(prior_transaction.txid(), 0),
                    ..TxIn::default()
                },
                TxIn {
                    previous_output: OutPoint::new(sponsor_transaction.txid(), 0),
                    ..TxIn::default()
                },
            ],
            output: vec![
                explicit_output(authority_asset, 1, successor_script.clone()),
                explicit_output(policy_asset, 900, sponsor_script.clone()),
                explicit_output(policy_asset, 100, Script::new()),
            ],
        };
        update.successor_transaction_id = transaction.txid().to_byte_array();
        let scripts = TruthcoinAnchorAuthorityScriptsV1 {
            prior_state_commitment: prior.commitment(),
            prior_script_sha256: Sha256::digest(prior_script.as_bytes()).into(),
            successor_state_commitment: successor.commitment(),
            successor_script_sha256: Sha256::digest(successor_script.as_bytes()).into(),
            sponsor_change_script_sha256: Sha256::digest(sponsor_script.as_bytes()).into(),
        };
        TruthcoinAnchorFixture {
            settlement: TruthcoinAnchorSettlementV1 {
                version: TRUTHCOIN_ANCHOR_SETTLEMENT_VERSION,
                transaction: encode::serialize(&transaction),
                prior_authority_transaction: encode::serialize(&prior_transaction),
                sponsor_previous_transaction: encode::serialize(&sponsor_transaction),
                sponsor_previous_vout: 0,
            },
            prior,
            successor,
            update,
            scripts,
            authentication,
            deployment,
            policy_asset,
        }
    }

    fn truthcoin_anchor_authentication() -> TruthcoinAuthenticationConfigV1 {
        TruthcoinAuthenticationConfigV1 {
            version: TruthcoinAuthenticationConfigV1::VERSION,
            source_git_commit_sha1: [1; 20],
            consensus_source_manifest_sha256: [18; 32],
            source_patch_manifest_sha256: [19; 32],
            sidechain_number: 13,
            bitcoin_checkpoint_hash: [16; 32],
            bitcoin_checkpoint_height: 100,
            bip300_checkpoint_state_hash: [24; 32],
            genesis_sidechain_block_hash: [17; 32],
            truthcoin_chain_id: [6; 32],
            truthcoin_branch_id: [7; 32],
            btc_usd_template_hash: [8; 32],
            lmsr_math_commitment: [9; 32],
            source_proof_program_id: [14; 32],
            selection_rule_hash: [15; 32],
            minimum_bitcoin_confirmations: 6,
            maximum_proof_bytes: 1_024,
        }
    }

    fn truthcoin_anchor_state(sequence: u64, configuration_hash: Hash32) -> TruthcoinAnchorStateV1 {
        let mut state = TruthcoinAnchorStateV1 {
            version: TruthcoinAnchorStateV1::VERSION,
            configuration_hash,
            sequence,
            bitcoin_checkpoint_hash: [2 + sequence as u8; 32],
            bitcoin_checkpoint_height: 100 + sequence,
            bitcoin_checkpoint_mtp: 1_000 + sequence,
            bitcoin_checkpoint_chainwork: [3 + sequence as u8; 32],
            truthcoin_genesis_hash: [5; 32],
            truthcoin_tip_hash: [6; 32],
            truthcoin_tip_height: 20,
            truthcoin_tip_parent_bitcoin_hash: [7; 32],
            canonical_path_root: [8; 32],
            replay_transcript_root: [9; 32],
            complete_state_root: [10; 32],
            decision_registry_root: [11; 32],
            market_registry_root: [12; 32],
            lmsr_state_root: [13; 32],
            sample_window_root: [14; 32],
            selected_anchor_commitment: [15; 32],
            selected_fast_market_commitment: [16; 32],
            oracle_certificate_commitment: [17; 32],
            last_update_elements_height: 50 + sequence,
            source_data_available_through_height: 100 + sequence,
            cumulative_update_root: [18; 32],
            last_update_proof_commitment: if sequence == 0 { [0; 32] } else { [33; 32] },
        };
        if sequence == 0 {
            state.last_update_proof_commitment = [0; 32];
        }
        state
    }

    fn state_test_script(commitment: Hash32) -> Script {
        let mut bytes = vec![0x51, 0x20];
        bytes.extend_from_slice(&commitment);
        Script::from(bytes)
    }

    fn explicit_output(asset: Hash32, amount: u64, script_pubkey: Script) -> TxOut {
        TxOut {
            asset: Asset::Explicit(AssetId::from_byte_array(asset)),
            value: Value::Explicit(amount),
            nonce: Nonce::Null,
            script_pubkey,
            witness: Default::default(),
        }
    }

    struct FrozenBondDeploymentFixtureV2 {
        deployment: FrozenBondDeploymentV2,
        frozen_asset: FrozenBondAssetV2,
        reissuance_token_asset_id: Hash32,
    }

    fn valid_frozen_bond_deployment_v2() -> FrozenBondDeploymentFixtureV2 {
        let inventory_script = Script::from(vec![0x51, 0x40]);
        let redemption_queue_script = Script::from(vec![0x51, 0x41]);
        let reissuance_token_burn_script = Script::from(vec![opcodes::all::OP_RETURN.into_u8()]);
        let mut issuance_input = TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([80; 32]), 2),
            ..TxIn::default()
        };
        issuance_input.asset_issuance.asset_entropy = [81; 32];
        issuance_input.asset_issuance.amount = Value::Explicit(BOND_FIXED_SUPPLY_ATOMS_V2);
        issuance_input.asset_issuance.inflation_keys = Value::Null;
        let bond_asset = issuance_input.issuance_ids().0;
        let inventory_abf = AssetBlindingFactor::from_slice(&[15; 32]).unwrap();
        let inventory_vbf = ValueBlindingFactor::from_slice(&[16; 32]).unwrap();
        let issuance_vbf = ValueBlindingFactor::last(
            &Secp256k1::new(),
            BOND_FIXED_SUPPLY_ATOMS_V2,
            AssetBlindingFactor::zero(),
            &[TxOutSecrets::new(
                bond_asset,
                inventory_abf,
                BOND_FIXED_SUPPLY_ATOMS_V2,
                inventory_vbf,
            )
            .value_blind_inputs()],
            &[],
        );
        issuance_input
            .blind_issuances_with_bfs(
                &Secp256k1::new(),
                issuance_vbf,
                ValueBlindingFactor::zero(),
                SecretKey::from_slice(&[17; 32]).unwrap(),
                SecretKey::from_slice(&[17; 32]).unwrap(),
            )
            .unwrap();
        issuance_input.asset_issuance.inflation_keys =
            Value::Explicit(BOND_REISSUANCE_TOKEN_BURN_AMOUNT_V2);
        let (bond_asset, reissuance_token_asset) = issuance_input.issuance_ids();
        let bond_asset_id = bond_asset.into_inner().to_byte_array();
        let reissuance_token_asset_id = reissuance_token_asset.into_inner().to_byte_array();

        let transaction = Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![issuance_input],
            output: vec![
                confidential_test_output(
                    bond_asset_id,
                    BOND_FIXED_SUPPLY_ATOMS_V2,
                    15,
                    16,
                    inventory_script.clone(),
                ),
                explicit_output(
                    reissuance_token_asset_id,
                    BOND_REISSUANCE_TOKEN_BURN_AMOUNT_V2,
                    reissuance_token_burn_script.clone(),
                ),
            ],
        };
        let frozen_asset = FrozenBondAssetV2 {
            version: FrozenBondAssetV2::VERSION,
            asset_id: bond_asset_id,
            inventory_vault_script_sha256: Sha256::digest(inventory_script.as_bytes()).into(),
            redemption_queue_script_sha256: Sha256::digest(redemption_queue_script.as_bytes())
                .into(),
            reissuance_token_burn_script_sha256: Sha256::digest(
                reissuance_token_burn_script.as_bytes(),
            )
            .into(),
        };
        let deployment = FrozenBondDeploymentV2 {
            version: BOND_DEPLOYMENT_VERSION,
            transaction: encode::serialize(&transaction),
            issuance_input_index: 0,
            inventory_output_index: 0,
            inventory_asset_blinding_factor: [15; 32],
            inventory_value_blinding_factor: [16; 32],
            issuance_value_blinding_factor: {
                let mut bytes = [0; 32];
                bytes.copy_from_slice(issuance_vbf.into_inner().as_ref());
                bytes
            },
            reissuance_token_burn_output_index: 1,
        };
        FrozenBondDeploymentFixtureV2 {
            deployment,
            frozen_asset,
            reissuance_token_asset_id,
        }
    }

    #[test]
    fn public_deployment_v3_preserves_supply_and_rejects_substitution() {
        use crate::public_deployment::{verify_public_bond_deployment, PUBLIC_DEPLOYMENT_VERSION};
        let mut input = TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([80; 32]), 2),
            ..TxIn::default()
        };
        input.asset_issuance.asset_entropy = [81; 32];
        input.asset_issuance.amount = Value::Explicit(BOND_FIXED_SUPPLY_ATOMS_V2);
        input.asset_issuance.inflation_keys = Value::Explicit(BOND_REISSUANCE_TOKEN_BURN_AMOUNT_V2);
        let (asset, token) = input.issuance_ids();
        let inventory = Script::from(vec![0x51, 0x40]);
        let burn = Script::from(vec![opcodes::all::OP_RETURN.into_u8()]);
        let frozen = FrozenBondAssetV2 {
            version: FrozenBondAssetV2::VERSION,
            asset_id: asset.into_inner().to_byte_array(),
            inventory_vault_script_sha256: Sha256::digest(inventory.as_bytes()).into(),
            redemption_queue_script_sha256: Sha256::digest([0x51, 0x41]).into(),
            reissuance_token_burn_script_sha256: Sha256::digest(burn.as_bytes()).into(),
        };
        let tx = Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![input],
            output: vec![
                explicit_output(frozen.asset_id, BOND_FIXED_SUPPLY_ATOMS_V2, inventory),
                explicit_output(token.into_inner().to_byte_array(), BOND_REISSUANCE_TOKEN_BURN_AMOUNT_V2, burn),
            ],
        };
        let deployment = FrozenBondDeploymentV2 {
            version: PUBLIC_DEPLOYMENT_VERSION,
            transaction: encode::serialize(&tx),
            issuance_input_index: 0,
            inventory_output_index: 0,
            inventory_asset_blinding_factor: [0; 32],
            inventory_value_blinding_factor: [0; 32],
            issuance_value_blinding_factor: [0; 32],
            reissuance_token_burn_output_index: 1,
        };
        let verified = verify_public_bond_deployment(&deployment, &frozen).unwrap();
        let mut template = tx.clone();
        template.input[0].asset_issuance = Default::default();
        let (composed, checked) = crate::public_deployment::compose_public_bond_deployment(
            template, 0, 0, 1, [81; 32], &frozen,
        ).unwrap();
        assert_eq!(composed.transaction, deployment.transaction);
        assert_eq!(checked.deployment_commitment, verified.deployment_commitment);
        assert!(crate::public_deployment::compose_public_bond_deployment(
            tx.clone(), 0, 0, 1, [81; 32], &frozen,
        ).is_err());
        assert_eq!(verified.transaction_id, tx.txid().to_byte_array());
        assert_eq!(verified.fixed_supply_atoms, BOND_FIXED_SUPPLY_ATOMS_V2);
        assert!(verify_frozen_bond_deployment_v2(&deployment, &frozen).is_err());
        let legacy = valid_frozen_bond_deployment_v2();
        assert!(verify_public_bond_deployment(&legacy.deployment, &legacy.frozen_asset).is_err());
        let mut wrong = deployment.clone();
        wrong.inventory_value_blinding_factor = [1; 32];
        assert!(verify_public_bond_deployment(&wrong, &frozen).is_err());
        for variant in 0..6 {
            let mut altered = tx.clone();
            match variant {
                0 => altered.output[0].value = Value::Explicit(BOND_FIXED_SUPPLY_ATOMS_V2 - 1),
                1 => altered.output.push(altered.output[0].clone()),
                2 => altered.output[1].script_pubkey = Script::from(vec![0x51]),
                3 => altered.input[0].asset_issuance.amount = Value::Explicit(BOND_FIXED_SUPPLY_ATOMS_V2 - 1),
                4 => altered.input.push(altered.input[0].clone()),
                _ => altered.output[0] = confidential_test_output(frozen.asset_id, BOND_FIXED_SUPPLY_ATOMS_V2, 15, 16, altered.output[0].script_pubkey.clone()),
            }
            let mut candidate = deployment.clone();
            candidate.transaction = encode::serialize(&altered);
            assert!(verify_public_bond_deployment(&candidate, &frozen).is_err(), "variant {variant}");
        }
    }

    struct BondSettlementFixtureV2 {
        settlement: BondSettlementV2,
        frozen_asset: FrozenBondAssetV2,
        subscription_script: Script,
    }

    fn valid_bond_settlement_v2() -> BondSettlementFixtureV2 {
        let asset_id = [41; 32];
        let inventory_script = Script::from(vec![0x51, 0x10]);
        let redemption_queue_script = Script::from(vec![0x51, 0x20]);
        let subscription_script = Script::from(vec![0x51, 0x30]);
        let inventory_script_sha256 = Sha256::digest(inventory_script.as_bytes()).into();
        let redemption_queue_script_sha256 =
            Sha256::digest(redemption_queue_script.as_bytes()).into();
        let subscription_script_sha256 = Sha256::digest(subscription_script.as_bytes()).into();
        let reissuance_token_burn_script_sha256 =
            Sha256::digest([opcodes::all::OP_RETURN.into_u8()]).into();
        let frozen_asset = FrozenBondAssetV2 {
            version: FrozenBondAssetV2::VERSION,
            asset_id,
            inventory_vault_script_sha256: inventory_script_sha256,
            redemption_queue_script_sha256,
            reissuance_token_burn_script_sha256,
        };
        frozen_asset.validate().unwrap();

        let inventory_previous_output =
            confidential_test_output(asset_id, 70, 1, 2, inventory_script.clone());
        let inventory_previous_transaction = Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![],
            output: vec![inventory_previous_output],
        };
        let redemption_previous_output =
            confidential_test_output(asset_id, 30, 11, 12, redemption_queue_script.clone());
        let redemption_previous_transaction = Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![],
            output: vec![redemption_previous_output],
        };

        let transaction = Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: OutPoint::new(inventory_previous_transaction.txid(), 0),
                    ..TxIn::default()
                },
                TxIn {
                    previous_output: OutPoint::new(redemption_previous_transaction.txid(), 0),
                    ..TxIn::default()
                },
            ],
            output: vec![
                confidential_test_output(asset_id, 40, 3, 4, inventory_script.clone()),
                confidential_test_output(asset_id, 30, 5, 6, subscription_script.clone()),
                confidential_test_output(asset_id, 10, 7, 8, redemption_queue_script),
                confidential_test_output(asset_id, 20, 9, 10, inventory_script),
            ],
        };
        let redemption_id = [61; 32];
        let settlement = BondSettlementV2 {
            version: BOND_SETTLEMENT_VERSION,
            transaction: encode::serialize(&transaction),
            bond_inputs: vec![
                BondInputOpeningV2 {
                    input_index: 0,
                    previous_transaction: encode::serialize(&inventory_previous_transaction),
                    previous_vout: 0,
                    amount: 70,
                    asset_blinding_factor: [1; 32],
                    value_blinding_factor: [2; 32],
                    role: BondInputRoleV2::InventoryVault,
                },
                BondInputOpeningV2 {
                    input_index: 1,
                    previous_transaction: encode::serialize(&redemption_previous_transaction),
                    previous_vout: 0,
                    amount: 30,
                    asset_blinding_factor: [11; 32],
                    value_blinding_factor: [12; 32],
                    role: BondInputRoleV2::QueuedRedemption { redemption_id },
                },
            ],
            bond_outputs: vec![
                BondOutputOpeningV2 {
                    output_index: 0,
                    amount: 40,
                    asset_blinding_factor: [3; 32],
                    value_blinding_factor: [4; 32],
                    role: BondOutputRoleV2::InventoryVaultChange,
                },
                BondOutputOpeningV2 {
                    output_index: 1,
                    amount: 30,
                    asset_blinding_factor: [5; 32],
                    value_blinding_factor: [6; 32],
                    role: BondOutputRoleV2::Subscription {
                        subscription_id: [62; 32],
                        recipient_script_sha256: subscription_script_sha256,
                    },
                },
                BondOutputOpeningV2 {
                    output_index: 2,
                    amount: 10,
                    asset_blinding_factor: [7; 32],
                    value_blinding_factor: [8; 32],
                    role: BondOutputRoleV2::QueuedRedemptionRemainder { redemption_id },
                },
                BondOutputOpeningV2 {
                    output_index: 3,
                    amount: 20,
                    asset_blinding_factor: [9; 32],
                    value_blinding_factor: [10; 32],
                    role: BondOutputRoleV2::RedemptionInventoryReturn { redemption_id },
                },
            ],
        };
        BondSettlementFixtureV2 {
            settlement,
            frozen_asset,
            subscription_script,
        }
    }

    fn confidential_test_output(
        asset_id: Hash32,
        amount: u64,
        asset_blinding_tag: u8,
        value_blinding_tag: u8,
        script_pubkey: Script,
    ) -> TxOut {
        let mut rng = thread_rng();
        let secp = Secp256k1::new();
        let asset_id = AssetId::from_byte_array(asset_id);
        let asset_blinding_factor =
            AssetBlindingFactor::from_slice(&[asset_blinding_tag; 32]).unwrap();
        let value_blinding_factor =
            ValueBlindingFactor::from_slice(&[value_blinding_tag; 32]).unwrap();
        let receiver_secret = SecretKey::new(&mut rng);
        let receiver_public = PublicKey::from_secret_key(&secp, &receiver_secret);
        let ephemeral_secret = SecretKey::new(&mut rng);
        let secrets = TxOutSecrets::new(
            asset_id,
            asset_blinding_factor,
            amount,
            value_blinding_factor,
        );
        let input_secrets = TxOutSecrets::new(
            asset_id,
            AssetBlindingFactor::zero(),
            amount,
            ValueBlindingFactor::zero(),
        );
        TxOut::with_txout_secrets(
            &mut rng,
            &secp,
            script_pubkey,
            receiver_public,
            ephemeral_secret,
            secrets,
            &[input_secrets],
        )
        .unwrap()
    }

    fn verify_reserve_aggregate_flow_v2(
        input_specs: &[(CollateralInputRoleV2, u64)],
        output_specs: &[(CollateralOutputRoleV2, u64)],
    ) -> VerifiedTransitionSettlementV2 {
        let usdd_asset_id = [0x81; 32];
        let bond_asset_id = [0x82; 32];
        let collateral_vault_script = Script::from(vec![0x51, 0x81]);
        let insurance_reserve_script = Script::from(vec![0x51, 0x82]);
        let inventory_script = Script::from(vec![0x51, 0x83]);
        let queue_script = Script::from(vec![0x51, 0x84]);
        let collateral_vault_script_sha256 =
            Sha256::digest(collateral_vault_script.as_bytes()).into();
        let insurance_reserve_script_sha256 =
            Sha256::digest(insurance_reserve_script.as_bytes()).into();
        let frozen_bond_asset = FrozenBondAssetV2 {
            version: FrozenBondAssetV2::VERSION,
            asset_id: bond_asset_id,
            inventory_vault_script_sha256: Sha256::digest(inventory_script.as_bytes()).into(),
            redemption_queue_script_sha256: Sha256::digest(queue_script.as_bytes()).into(),
            reissuance_token_burn_script_sha256: Sha256::digest(
                [opcodes::all::OP_RETURN.into_u8()],
            )
            .into(),
        };

        let mut next_blinding_tag = 1u8;
        let mut transaction_inputs = vec![transition_input(0x91), transition_input(0x92)];
        let mut collateral_inputs = Vec::with_capacity(input_specs.len());
        for (role, amount) in input_specs.iter().copied() {
            let asset_blinding_tag = next_blinding_tag;
            let value_blinding_tag = next_blinding_tag + 1;
            next_blinding_tag += 2;
            let script = match role {
                CollateralInputRoleV2::CollateralVault => collateral_vault_script.clone(),
                CollateralInputRoleV2::InsuranceReserve => insurance_reserve_script.clone(),
            };
            let previous = Transaction {
                version: 2,
                lock_time: elements::LockTime::ZERO,
                input: vec![],
                output: vec![confidential_test_output(
                    usdd_asset_id,
                    amount,
                    asset_blinding_tag,
                    value_blinding_tag,
                    script,
                )],
            };
            let input_index = u32::try_from(transaction_inputs.len()).unwrap();
            transaction_inputs.push(TxIn {
                previous_output: OutPoint::new(previous.txid(), 0),
                ..TxIn::default()
            });
            collateral_inputs.push(CollateralInputOpeningV2 {
                input_index,
                previous_transaction: encode::serialize(&previous),
                previous_vout: 0,
                amount,
                asset_blinding_factor: [asset_blinding_tag; 32],
                value_blinding_factor: [value_blinding_tag; 32],
                role,
            });
        }

        let placeholder_output = || TxOut {
            asset: Asset::Explicit(AssetId::from_byte_array([0x90; 32])),
            value: Value::Explicit(1),
            nonce: Nonce::Null,
            script_pubkey: Script::from(vec![0x51]),
            witness: Default::default(),
        };
        let mut cursor_payload = CURSOR_MARKER_MAGIC.to_vec();
        cursor_payload.push(CURSOR_MARKER_VERSION);
        cursor_payload.extend_from_slice(&0u64.to_le_bytes());
        cursor_payload.extend_from_slice(&0u64.to_le_bytes());
        let mut cursor_output = placeholder_output();
        cursor_output.script_pubkey = marker_script(cursor_payload);
        let mut transaction_outputs = vec![
            placeholder_output(),
            placeholder_output(),
            placeholder_output(),
            cursor_output,
        ];
        let mut collateral_outputs = Vec::with_capacity(output_specs.len());
        for (role, amount) in output_specs.iter().copied() {
            let asset_blinding_tag = next_blinding_tag;
            let value_blinding_tag = next_blinding_tag + 1;
            next_blinding_tag += 2;
            let script = match role {
                CollateralOutputRoleV2::CollateralVaultChange => collateral_vault_script.clone(),
                CollateralOutputRoleV2::InsuranceReserveChange => insurance_reserve_script.clone(),
                _ => panic!("reserve aggregate fixture accepts only vault/reserve change roles"),
            };
            let output_index = u32::try_from(transaction_outputs.len()).unwrap();
            transaction_outputs.push(confidential_test_output(
                usdd_asset_id,
                amount,
                asset_blinding_tag,
                value_blinding_tag,
                script,
            ));
            collateral_outputs.push(CollateralOutputOpeningV2 {
                output_index,
                amount,
                asset_blinding_factor: [asset_blinding_tag; 32],
                value_blinding_factor: [value_blinding_tag; 32],
                role,
            });
        }

        let transaction = Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: transaction_inputs,
            output: transaction_outputs,
        };
        let settlement = TransitionSettlementV2 {
            version: TRANSITION_SETTLEMENT_V2_VERSION,
            transaction: encode::serialize(&transaction),
            collateral_inputs,
            collateral_outputs,
            bond_inputs: vec![],
            bond_outputs: vec![],
        };
        verify_transition_settlement_v2(
            &settlement,
            &[],
            &[],
            usdd_asset_id,
            collateral_vault_script_sha256,
            insurance_reserve_script_sha256,
            &frozen_bond_asset,
        )
        .unwrap()
    }

    struct TransitionSettlementFixtureV2 {
        settlement: TransitionSettlementV2,
        actions: Vec<BondSettlementActionV2>,
        usdd_asset_id: Hash32,
        collateral_vault_script_sha256: Hash32,
        insurance_reserve_script_sha256: Hash32,
        subscription_recipient_script_sha256: Hash32,
        redemption_recipient_script_sha256: Hash32,
        frozen_bond_asset: FrozenBondAssetV2,
    }

    fn redemption_lifecycle_settlement_v2(cancel: bool) -> TransitionSettlementFixtureV2 {
        let usdd_asset_id = [111; 32];
        let bond_asset_id = [112; 32];
        let collateral_vault_script = Script::from(vec![0x51, 0x60]);
        let insurance_reserve_script = Script::from(vec![0x51, 0x61]);
        let inventory_script = Script::from(vec![0x51, 0x62]);
        let queue_script = Script::from(vec![0x51, 0x63]);
        let holder_script = Script::from(vec![0x51, 0x64]);
        let return_script = Script::from(vec![0x51, 0x65]);
        let destination_script = Script::from(vec![0x51, 0x66]);
        let holder_script_sha256 = Sha256::digest(holder_script.as_bytes()).into();
        let return_script_sha256 = Sha256::digest(return_script.as_bytes()).into();
        let destination_script_sha256 = Sha256::digest(destination_script.as_bytes()).into();
        let frozen_bond_asset = FrozenBondAssetV2 {
            version: FrozenBondAssetV2::VERSION,
            asset_id: bond_asset_id,
            inventory_vault_script_sha256: Sha256::digest(inventory_script.as_bytes()).into(),
            redemption_queue_script_sha256: Sha256::digest(queue_script.as_bytes()).into(),
            reissuance_token_burn_script_sha256: Sha256::digest(
                [opcodes::all::OP_RETURN.into_u8()],
            )
            .into(),
        };
        let previous_script = if cancel {
            queue_script.clone()
        } else {
            holder_script
        };
        let previous = Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![],
            output: vec![confidential_test_output(
                bond_asset_id,
                25,
                25,
                26,
                previous_script,
            )],
        };
        let placeholder_output = || TxOut {
            asset: Asset::Explicit(AssetId::from_byte_array([9; 32])),
            value: Value::Explicit(1),
            nonce: Nonce::Null,
            script_pubkey: Script::from(vec![0x51]),
            witness: Default::default(),
        };
        let mut cursor_payload = CURSOR_MARKER_MAGIC.to_vec();
        cursor_payload.push(CURSOR_MARKER_VERSION);
        cursor_payload.extend_from_slice(&0u64.to_le_bytes());
        cursor_payload.extend_from_slice(&0u64.to_le_bytes());
        let mut cursor_output = placeholder_output();
        cursor_output.script_pubkey = marker_script(cursor_payload);
        let output_script = if cancel { return_script } else { queue_script };
        let transaction = Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![
                transition_input(113),
                transition_input(114),
                TxIn {
                    previous_output: OutPoint::new(previous.txid(), 0),
                    ..TxIn::default()
                },
            ],
            output: vec![
                placeholder_output(),
                placeholder_output(),
                placeholder_output(),
                cursor_output,
                confidential_test_output(bond_asset_id, 25, 27, 28, output_script),
            ],
        };
        let redemption_id = [115; 32];
        let claimant = [116; 32];
        let cancellation_id = [117; 32];
        let staging_intent_id = [118; 32];
        let source_txid = previous.txid().to_byte_array();
        let source_vout = 0;
        let refund_not_before_parent_height = 200;
        let source_authorization_commitment =
            bond_inbox_staging_source_authorization_commitment_v2(
                &encode::serialize(&previous.output[0]),
                staging_intent_id,
                return_script_sha256,
                refund_not_before_parent_height,
            )
            .unwrap();
        let (input_role, output_role, action) = if cancel {
            (
                BondInputRoleV2::QueuedRedemption { redemption_id },
                BondOutputRoleV2::CancelledRedemptionReturn {
                    redemption_id,
                    claimant,
                    recipient_script_sha256: return_script_sha256,
                    cancellation_id,
                },
                BondSettlementActionV2::CancelRedemption {
                    redemption_id,
                    claimant,
                    bond_share_amount: 25,
                    recipient_script_sha256: return_script_sha256,
                    cancellation_id,
                },
            )
        } else {
            (
                BondInputRoleV2::StagedRedemptionEnqueue {
                    redemption_id,
                    staging_intent_id,
                    claimant,
                    staging_script_sha256: holder_script_sha256,
                    source_txid,
                    source_vout,
                },
                BondOutputRoleV2::QueuedRedemptionEntry {
                    redemption_id,
                    staging_intent_id,
                    claimant,
                    destination_script_sha256,
                },
                BondSettlementActionV2::EnqueueRedemption {
                    redemption_id,
                    staging_intent_id,
                    claimant,
                    bond_share_amount: 25,
                    staging_script_sha256: holder_script_sha256,
                    source_txid,
                    source_vout,
                    source_authorization_commitment,
                    refund_script_sha256: return_script_sha256,
                    refund_not_before_parent_height,
                    destination_script_sha256,
                },
            )
        };
        TransitionSettlementFixtureV2 {
            settlement: TransitionSettlementV2 {
                version: TRANSITION_SETTLEMENT_V2_VERSION,
                transaction: encode::serialize(&transaction),
                collateral_inputs: vec![],
                collateral_outputs: vec![],
                bond_inputs: vec![BondInputOpeningV2 {
                    input_index: 2,
                    previous_transaction: encode::serialize(&previous),
                    previous_vout: 0,
                    amount: 25,
                    asset_blinding_factor: [25; 32],
                    value_blinding_factor: [26; 32],
                    role: input_role,
                }],
                bond_outputs: vec![BondOutputOpeningV2 {
                    output_index: 4,
                    amount: 25,
                    asset_blinding_factor: [27; 32],
                    value_blinding_factor: [28; 32],
                    role: output_role,
                }],
            },
            actions: vec![action],
            usdd_asset_id,
            collateral_vault_script_sha256: Sha256::digest(collateral_vault_script.as_bytes())
                .into(),
            insurance_reserve_script_sha256: Sha256::digest(insurance_reserve_script.as_bytes())
                .into(),
            subscription_recipient_script_sha256: [1; 32],
            redemption_recipient_script_sha256: destination_script_sha256,
            frozen_bond_asset,
        }
    }

    fn valid_transition_settlement_v2() -> TransitionSettlementFixtureV2 {
        let usdd_asset_id = [31; 32];
        let bond_asset_id = [32; 32];
        let collateral_vault_script = Script::from(vec![0x51, 0x50]);
        let insurance_reserve_script = Script::from(vec![0x51, 0x51]);
        let bond_inventory_script = Script::from(vec![0x51, 0x52]);
        let bond_queue_script = Script::from(vec![0x51, 0x53]);
        let subscription_recipient_script = Script::from(vec![0x51, 0x54]);
        let redemption_recipient_script = Script::from(vec![0x51, 0x55]);
        let collateral_vault_script_sha256 =
            Sha256::digest(collateral_vault_script.as_bytes()).into();
        let insurance_reserve_script_sha256 =
            Sha256::digest(insurance_reserve_script.as_bytes()).into();
        let subscription_recipient_script_sha256 =
            Sha256::digest(subscription_recipient_script.as_bytes()).into();
        let redemption_recipient_script_sha256 =
            Sha256::digest(redemption_recipient_script.as_bytes()).into();
        let frozen_bond_asset = FrozenBondAssetV2 {
            version: FrozenBondAssetV2::VERSION,
            asset_id: bond_asset_id,
            inventory_vault_script_sha256: Sha256::digest(bond_inventory_script.as_bytes()).into(),
            redemption_queue_script_sha256: Sha256::digest(bond_queue_script.as_bytes()).into(),
            reissuance_token_burn_script_sha256: Sha256::digest(
                [opcodes::all::OP_RETURN.into_u8()],
            )
            .into(),
        };

        let collateral_previous = Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![],
            output: vec![confidential_test_output(
                usdd_asset_id,
                100,
                1,
                2,
                collateral_vault_script.clone(),
            )],
        };
        let insurance_previous = Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![],
            output: vec![confidential_test_output(
                usdd_asset_id,
                50,
                3,
                4,
                insurance_reserve_script.clone(),
            )],
        };
        let bond_inventory_previous = Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![],
            output: vec![confidential_test_output(
                bond_asset_id,
                100,
                5,
                6,
                bond_inventory_script.clone(),
            )],
        };
        let bond_queue_previous = Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![],
            output: vec![confidential_test_output(
                bond_asset_id,
                30,
                7,
                8,
                bond_queue_script.clone(),
            )],
        };

        let placeholder_output = || TxOut {
            asset: Asset::Explicit(AssetId::from_byte_array([9; 32])),
            value: Value::Explicit(1),
            nonce: Nonce::Null,
            script_pubkey: Script::from(vec![0x51]),
            witness: Default::default(),
        };
        let mut cursor_payload = CURSOR_MARKER_MAGIC.to_vec();
        cursor_payload.push(CURSOR_MARKER_VERSION);
        cursor_payload.extend_from_slice(&0u64.to_le_bytes());
        cursor_payload.extend_from_slice(&0u64.to_le_bytes());
        let mut cursor_output = placeholder_output();
        cursor_output.script_pubkey = marker_script(cursor_payload);
        let transaction = Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![
                transition_input(90),
                transition_input(91),
                TxIn {
                    previous_output: OutPoint::new(collateral_previous.txid(), 0),
                    ..TxIn::default()
                },
                TxIn {
                    previous_output: OutPoint::new(insurance_previous.txid(), 0),
                    ..TxIn::default()
                },
                TxIn {
                    previous_output: OutPoint::new(bond_inventory_previous.txid(), 0),
                    ..TxIn::default()
                },
                TxIn {
                    previous_output: OutPoint::new(bond_queue_previous.txid(), 0),
                    ..TxIn::default()
                },
            ],
            output: vec![
                placeholder_output(),
                placeholder_output(),
                placeholder_output(),
                cursor_output,
                confidential_test_output(usdd_asset_id, 60, 9, 10, collateral_vault_script),
                confidential_test_output(
                    usdd_asset_id,
                    20,
                    11,
                    12,
                    insurance_reserve_script.clone(),
                ),
                confidential_test_output(usdd_asset_id, 55, 13, 14, insurance_reserve_script),
                confidential_test_output(usdd_asset_id, 15, 15, 16, redemption_recipient_script),
                confidential_test_output(bond_asset_id, 80, 17, 18, bond_inventory_script.clone()),
                confidential_test_output(bond_asset_id, 20, 19, 20, subscription_recipient_script),
                confidential_test_output(bond_asset_id, 10, 21, 22, bond_queue_script),
                confidential_test_output(bond_asset_id, 20, 23, 24, bond_inventory_script),
            ],
        };
        let subscription_id = [60; 32];
        let redemption_id = [61; 32];
        let settlement = TransitionSettlementV2 {
            version: TRANSITION_SETTLEMENT_V2_VERSION,
            transaction: encode::serialize(&transaction),
            collateral_inputs: vec![
                CollateralInputOpeningV2 {
                    input_index: 2,
                    previous_transaction: encode::serialize(&collateral_previous),
                    previous_vout: 0,
                    amount: 100,
                    asset_blinding_factor: [1; 32],
                    value_blinding_factor: [2; 32],
                    role: CollateralInputRoleV2::CollateralVault,
                },
                CollateralInputOpeningV2 {
                    input_index: 3,
                    previous_transaction: encode::serialize(&insurance_previous),
                    previous_vout: 0,
                    amount: 50,
                    asset_blinding_factor: [3; 32],
                    value_blinding_factor: [4; 32],
                    role: CollateralInputRoleV2::InsuranceReserve,
                },
            ],
            collateral_outputs: vec![
                CollateralOutputOpeningV2 {
                    output_index: 4,
                    amount: 60,
                    asset_blinding_factor: [9; 32],
                    value_blinding_factor: [10; 32],
                    role: CollateralOutputRoleV2::CollateralVaultChange,
                },
                CollateralOutputOpeningV2 {
                    output_index: 5,
                    amount: 20,
                    asset_blinding_factor: [11; 32],
                    value_blinding_factor: [12; 32],
                    role: CollateralOutputRoleV2::BondSubscriptionContribution { subscription_id },
                },
                CollateralOutputOpeningV2 {
                    output_index: 6,
                    amount: 55,
                    asset_blinding_factor: [13; 32],
                    value_blinding_factor: [14; 32],
                    role: CollateralOutputRoleV2::InsuranceReserveChange,
                },
                CollateralOutputOpeningV2 {
                    output_index: 7,
                    amount: 15,
                    asset_blinding_factor: [15; 32],
                    value_blinding_factor: [16; 32],
                    role: CollateralOutputRoleV2::BondRedemptionPayment {
                        redemption_id,
                        recipient_script_sha256: redemption_recipient_script_sha256,
                    },
                },
            ],
            bond_inputs: vec![
                BondInputOpeningV2 {
                    input_index: 4,
                    previous_transaction: encode::serialize(&bond_inventory_previous),
                    previous_vout: 0,
                    amount: 100,
                    asset_blinding_factor: [5; 32],
                    value_blinding_factor: [6; 32],
                    role: BondInputRoleV2::InventoryVault,
                },
                BondInputOpeningV2 {
                    input_index: 5,
                    previous_transaction: encode::serialize(&bond_queue_previous),
                    previous_vout: 0,
                    amount: 30,
                    asset_blinding_factor: [7; 32],
                    value_blinding_factor: [8; 32],
                    role: BondInputRoleV2::QueuedRedemption { redemption_id },
                },
            ],
            bond_outputs: vec![
                BondOutputOpeningV2 {
                    output_index: 8,
                    amount: 80,
                    asset_blinding_factor: [17; 32],
                    value_blinding_factor: [18; 32],
                    role: BondOutputRoleV2::InventoryVaultChange,
                },
                BondOutputOpeningV2 {
                    output_index: 9,
                    amount: 20,
                    asset_blinding_factor: [19; 32],
                    value_blinding_factor: [20; 32],
                    role: BondOutputRoleV2::Subscription {
                        subscription_id,
                        recipient_script_sha256: subscription_recipient_script_sha256,
                    },
                },
                BondOutputOpeningV2 {
                    output_index: 10,
                    amount: 10,
                    asset_blinding_factor: [21; 32],
                    value_blinding_factor: [22; 32],
                    role: BondOutputRoleV2::AuthenticatedQueuedRedemptionRemainder {
                        redemption_id,
                        claimant: [63; 32],
                        destination_script_sha256: redemption_recipient_script_sha256,
                    },
                },
                BondOutputOpeningV2 {
                    output_index: 11,
                    amount: 20,
                    asset_blinding_factor: [23; 32],
                    value_blinding_factor: [24; 32],
                    role: BondOutputRoleV2::RedemptionInventoryReturn { redemption_id },
                },
            ],
        };
        let actions = vec![
            BondSettlementActionV2::Subscription {
                subscription_id,
                usdd_contribution_amount: 20,
                bond_share_amount: 20,
                recipient_script_sha256: subscription_recipient_script_sha256,
            },
            BondSettlementActionV2::ExecuteRedemption {
                redemption_id,
                claimant: [63; 32],
                queued_share_amount: 30,
                redeemed_share_amount: 20,
                remainder_share_amount: 10,
                usdd_payment_amount: 15,
                destination_script_sha256: redemption_recipient_script_sha256,
            },
        ];
        TransitionSettlementFixtureV2 {
            settlement,
            actions,
            usdd_asset_id,
            collateral_vault_script_sha256,
            insurance_reserve_script_sha256,
            subscription_recipient_script_sha256,
            redemption_recipient_script_sha256,
            frozen_bond_asset,
        }
    }

    fn valid_transition_settlement() -> (TransitionSettlementV1, Hash32, Hash32) {
        let mut rng = thread_rng();
        let secp = Secp256k1::new();
        let asset_id = AssetId::from_byte_array([3; 32]);
        let mut vault_script_bytes = vec![0x51, 0x20];
        vault_script_bytes.extend_from_slice(&[7; 32]);
        let vault_script = Script::from(vault_script_bytes);
        let abf = AssetBlindingFactor::from_slice(&[1; 32]).unwrap();
        let vbf = ValueBlindingFactor::from_slice(&[2; 32]).unwrap();
        let receiver_secret = SecretKey::new(&mut rng);
        let receiver_public = PublicKey::from_secret_key(&secp, &receiver_secret);
        let ephemeral_secret = SecretKey::new(&mut rng);
        let secrets = TxOutSecrets::new(asset_id, abf, 100, vbf);
        let input_secrets = TxOutSecrets::new(
            asset_id,
            AssetBlindingFactor::zero(),
            100,
            ValueBlindingFactor::zero(),
        );
        let vault_output = TxOut::with_txout_secrets(
            &mut rng,
            &secp,
            vault_script.clone(),
            receiver_public,
            ephemeral_secret,
            secrets,
            &[input_secrets],
        )
        .unwrap();
        let previous_transaction = Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![],
            output: vec![vault_output.clone()],
        };

        let placeholder_output = || TxOut {
            asset: Asset::Explicit(AssetId::from_byte_array([9; 32])),
            value: Value::Explicit(1),
            nonce: Nonce::Null,
            script_pubkey: Script::from(vec![0x51]),
            witness: Default::default(),
        };
        let mut cursor_payload = CURSOR_MARKER_MAGIC.to_vec();
        cursor_payload.push(CURSOR_MARKER_VERSION);
        cursor_payload.extend_from_slice(&0u64.to_le_bytes());
        cursor_payload.extend_from_slice(&0u64.to_le_bytes());
        let mut cursor_output = placeholder_output();
        cursor_output.script_pubkey = marker_script(cursor_payload);
        let transaction = Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![
                transition_input(1),
                transition_input(2),
                TxIn {
                    previous_output: OutPoint::new(previous_transaction.txid(), 0),
                    ..TxIn::default()
                },
            ],
            output: vec![
                placeholder_output(),
                placeholder_output(),
                placeholder_output(),
                vault_output,
                cursor_output,
            ],
        };
        let vault_script_hash = Sha256::digest(vault_script.as_bytes()).into();
        let settlement = TransitionSettlementV1 {
            version: TRANSITION_SETTLEMENT_VERSION,
            transaction: encode::serialize(&transaction),
            collateral_inputs: vec![CollateralInputOpeningV1 {
                input_index: 2,
                previous_transaction: encode::serialize(&previous_transaction),
                previous_vout: 0,
                amount: 100,
                asset_blinding_factor: [1; 32],
                value_blinding_factor: [2; 32],
            }],
            collateral_outputs: vec![CollateralOutputOpeningV1 {
                output_index: 3,
                amount: 100,
                asset_blinding_factor: [1; 32],
                value_blinding_factor: [2; 32],
                role: CollateralOutputRoleV1::VaultChange,
            }],
        };
        assert!(verify_transition_settlement(
            &settlement,
            &[],
            asset_id.into_inner().to_byte_array(),
            vault_script_hash,
        )
        .is_ok());
        (
            settlement,
            asset_id.into_inner().to_byte_array(),
            vault_script_hash,
        )
    }

    fn transition_input(tag: u8) -> TxIn {
        TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([tag; 32]), 0),
            ..TxIn::default()
        }
    }

    struct BondInboxSourceFixtureV2 {
        configuration: FrozenConfigurationV2,
        entry: BondInboxEntryV2,
        source_transaction: Vec<u8>,
        bundle: Vec<u8>,
        receipts: Vec<BondInboxCustodyReceiptV2>,
    }

    struct SuccessorBondInboxSourceFixtureV2 {
        configuration: FrozenConfigurationV2,
        entry: SuccessorBondInboxEntryV2,
        source_transaction: Vec<u8>,
        bundle: Vec<u8>,
        receipts: Vec<BondInboxCustodyReceiptV2>,
        custodian_public: Vec<ecx_witness_availability::CustodianPublic>,
    }

    fn bond_inbox_source_test_configuration_v2() -> FrozenConfigurationV2 {
        let matcher_secret = SecretKey::from_slice(&[31; 32]).unwrap();
        let matcher_keypair =
            elements::secp256k1_zkp::Keypair::from_secret_key(&Secp256k1::new(), &matcher_secret);
        let (matcher_xonly, _) =
            elements::secp256k1_zkp::XOnlyPublicKey::from_keypair(&matcher_keypair);
        let base = FrozenConfigurationV1 {
            version: FrozenConfigurationV1::VERSION,
            chain_id: [1; 32],
            market: ecx_protocol_core::ECX_USDD_MARKET,
            ecx_asset_id: [2; 32],
            usdd_asset_id: [3; 32],
            policy_asset_id: [4; 32],
            state_authority_asset_id: [5; 32],
            usdd_checkpoint: UsddCheckpointConfigV1 {
                version: UsddCheckpointConfigV1::VERSION,
                ethereum_light_client_configuration_hash: [24; 32],
                authority_configuration_hash: [25; 32],
                maximum_checkpoint_age_seconds: USDD_MAX_CHECKPOINT_AGE_SECONDS,
            },
            risk: RiskParams::default(),
            availability: AvailabilityConfigV1 {
                version: AvailabilityConfigV1::VERSION,
                scheme_hash: ecx_protocol_core::AVAILABILITY_SCHEME_HASH_V1,
                custodian_registry_hash: [20; 32],
                recovery_threshold: AVAILABILITY_RECOVERY_THRESHOLD,
                custodian_count: AVAILABILITY_CUSTODIAN_COUNT,
                maximum_witness_bytes: MAX_AVAILABILITY_WITNESS_BYTES,
            },
            truthcoin_authentication: truthcoin_anchor_authentication(),
            truthcoin_anchor_deployment: TruthcoinAnchorDeploymentV1 {
                version: TruthcoinAnchorDeploymentV1::VERSION,
                authority_asset_id: [21; 32],
                authority_amount: 1,
                script_tree_configuration_hash: [22; 32],
            },
            oracle: HybridOracleConfigV1 {
                version: 1,
                truthcoin_chain_id: [6; 32],
                truthcoin_branch_id: [7; 32],
                btc_usd_template_hash: [8; 32],
                lmsr_math_commitment: [9; 32],
                schedule_origin_mtp: 1,
                epoch_length_seconds: 600,
                minimum_source_confirmations: 6,
                maximum_anchor_age_seconds: 3_600,
                maximum_snapshot_age_seconds: 120,
                minimum_lmsr_b: 1_000,
                minimum_sample_count: 3,
                base_lmsr_weight_ppm: 0,
                maximum_lmsr_weight_ppm: PPM_DENOMINATOR as u32,
                initial_anchor_band_bps: 100,
                maximum_anchor_band_bps: 2_000,
                risk_haircut_bps: 100,
                boundary_guard_ppb: 10_000,
                maximum_unanchored_deviation_bps: 5_000,
                ecx_satoshis_per_coin: 1_000,
                usdd_usd_price_units: ecx_protocol_core::PRICE_SCALE,
            },
            matcher: CentralMatcherConfigV1 {
                version: CentralMatcherConfigV1::VERSION,
                key_epoch: 0,
                signer: XOnlyKey(matcher_xonly.serialize()),
                genesis_sequence: 0,
                genesis_receipt_hash: [10; 32],
                forced_inclusion_blocks: 6,
            },
            forced_action_domain: [11; 32],
            deposit_inbox_domain: [12; 32],
            collateral_vault_script_sha256: [13; 32],
            maximum_transition_actions: MAX_TRANSITION_ACTIONS,
        };
        let internal_key = ecx_protocol_core::BOND_INBOX_REDEMPTION_STAGING_NUMS_INTERNAL_KEY_V2;
        let process_cmr = [30; 32];
        let refund_cmr = [32; 32];
        let staging_template = bond_inbox_redemption_staging_descriptor_commitment_v2(
            ecx_protocol_core::BOND_INBOX_REDEMPTION_STAGING_RENDERER_DOMAIN_V2,
            BOND_INBOX_REDEMPTION_STAGING_TAPLEAF_VERSION_V2,
            internal_key,
            process_cmr,
            refund_cmr,
        )
        .unwrap();
        let configuration = FrozenConfigurationV2 {
            version: FrozenConfigurationV2::VERSION,
            base,
            collateral_vault_covenant_cmr: [55; 32],
            bond_asset_id: [40; 32],
            bond_deployment_commitment: [41; 32],
            bond_inventory_script_sha256: [42; 32],
            bond_redemption_queue_script_sha256: [43; 32],
            bond_inbox_redemption_staging_template_commitment: staging_template,
            bond_inbox_redemption_staging_renderer_domain:
                ecx_protocol_core::BOND_INBOX_REDEMPTION_STAGING_RENDERER_DOMAIN_V2,
            bond_inbox_redemption_staging_internal_key: internal_key,
            bond_inbox_redemption_staging_tapleaf_version:
                BOND_INBOX_REDEMPTION_STAGING_TAPLEAF_VERSION_V2,
            bond_inbox_redemption_staging_process_cmr: process_cmr,
            bond_inbox_redemption_staging_refund_cmr: refund_cmr,
            bond_inbox_refund_minimum_parent_blocks: BOND_INBOX_REFUND_MINIMUM_PARENT_BLOCKS_V2,
            insurance_reserve_script_sha256: [44; 32],
            insurance_reserve_covenant_cmr: [54; 32],
            destroyed_reissuance_token_script_sha256: [45; 32],
            bond_inbox_domain: [46; 32],
            bond_inbox_custody_receipt_codec_hash: [47; 32],
            bond_inbox_inclusion_blocks: BOND_INBOX_INCLUSION_BLOCKS_V2,
            bond_inbox_max_bundle_bytes: MAX_BOND_INBOX_BUNDLE_BYTES_V2,
            bond_inbox_max_entries_per_sidechain_block:
                BOND_INBOX_MAX_ENTRIES_PER_SIDECHAIN_BLOCK_V2,
            bond_inbox_max_unique_source_witness_bytes_per_sidechain_block:
                BOND_INBOX_MAX_UNIQUE_SOURCE_WITNESS_BYTES_PER_SIDECHAIN_BLOCK_V2,
            bond_inbox_max_unique_source_transaction_bytes_per_sidechain_block:
                BOND_INBOX_MAX_UNIQUE_SOURCE_TRANSACTION_BYTES_PER_SIDECHAIN_BLOCK_V2,
            bond_inbox_max_pending_entries_per_transition:
                BOND_INBOX_MAX_PENDING_ENTRIES_PER_TRANSITION_V2,
            bond_inbox_max_consumed_entries_per_transition:
                BOND_INBOX_MAX_CONSUMED_ENTRIES_PER_TRANSITION_V2,
            bond_redemption_max_queue_entries: BOND_REDEMPTION_MAX_QUEUE_ENTRIES_V2,
            matcher_execution_inclusion_parent_blocks: MATCHER_EXECUTION_INCLUSION_PARENT_BLOCKS_V2,
            ecx_btc_conversion_program_id: [48; 32],
            usdd_usd_conversion_program_id: [49; 32],
            ecx_btc_redemption_covenant_commitment: [50; 32],
            ecx_btc_source_checkpoint_commitment: [51; 32],
            usdd_usd_redemption_covenant_commitment: [52; 32],
            usdd_usd_source_checkpoint_commitment: [53; 32],
            maximum_conversion_age_seconds: 3_600,
            maximum_conversion_proof_bytes: 1_024,
            recursive_proof_marker_bytes: RECURSIVE_PROOF_MARKER_BYTES_V2,
            fixed_supply_atoms: BOND_FIXED_SUPPLY_ATOMS,
            redemption_delay_parent_blocks: BOND_REDEMPTION_DELAY_PARENT_BLOCKS,
        };
        configuration.validate().unwrap();
        configuration
    }

    #[test]
    fn frozen_v2_profile_rejects_availability_or_escape_window_substitution() {
        let configuration = bond_inbox_source_test_configuration_v2();
        configuration.validate().unwrap();

        let mut wrong_scheme = configuration.clone();
        wrong_scheme.base.availability.scheme_hash[0] ^= 1;
        assert_eq!(
            wrong_scheme.validate(),
            Err(ProtocolError::InvalidBondState)
        );

        let mut wrong_escape_window = configuration;
        wrong_escape_window.base.matcher.forced_inclusion_blocks += 1;
        assert_eq!(
            wrong_escape_window.validate(),
            Err(ProtocolError::InvalidBondState)
        );
    }

    fn bond_inbox_source_transaction_fixture_v2() -> BondInboxSourceFixtureV2 {
        let configuration = bond_inbox_source_test_configuration_v2();
        let signer_secret = SecretKey::from_slice(&[54; 32]).unwrap();
        let signer_keypair =
            elements::secp256k1_zkp::Keypair::from_secret_key(&Secp256k1::new(), &signer_secret);
        let (signer, _) = elements::secp256k1_zkp::XOnlyPublicKey::from_keypair(&signer_keypair);
        let bundle = vec![0x61; 128];
        let receipts = (0..3)
            .map(|custodian_index| {
                let mut exact_receipt_bytes = vec![0x70 + custodian_index; 138];
                exact_receipt_bytes[0] = 1;
                exact_receipt_bytes[73] = custodian_index + 1;
                BondInboxCustodyReceiptV2 {
                    custodian_index,
                    exact_receipt_bytes,
                }
            })
            .collect::<Vec<_>>();
        let staging_intent_id = [55; 32];
        let refund_script_sha256 = [56; 32];
        let refund_not_before_parent_height = 1_012;
        let staging_vout = 0;
        let renderer_input = BondInboxRedemptionStagingRendererInputV2 {
            chain_id: configuration.base.chain_id,
            configuration_hash: configuration.digest(),
            marker_signer: XOnlyKey(signer.serialize()),
            stable_intent_id: staging_intent_id,
            staging_vout,
            refund_script_sha256,
            refund_not_before_parent_height,
        };
        let staging = confidential_test_txout_v2(
            &configuration,
            renderer_input,
            configuration.bond_asset_id,
            400,
        );
        let source_authorization_commitment =
            bond_inbox_staging_source_authorization_commitment_v2(
                &encode::serialize(&staging),
                staging_intent_id,
                refund_script_sha256,
                refund_not_before_parent_height,
            )
            .unwrap();
        let mut marker = BondInboxMarkerV2 {
            version: BOND_INBOX_MARKER_VERSION,
            kind: BondInboxActionKindV2::RedemptionEnqueue,
            chain_id: configuration.base.chain_id,
            configuration_hash: configuration.digest(),
            signer: XOnlyKey(signer.serialize()),
            action_id: [57; 32],
            staging_intent_id,
            staging_vout,
            refund_script_sha256,
            refund_not_before_parent_height,
            payload_commitment: [58; 32],
            availability_scheme_hash: configuration.base.availability.scheme_hash,
            availability_custodian_registry_hash: configuration
                .base
                .availability
                .custodian_registry_hash,
            availability_bundle_root: bond_inbox_availability_bundle_root_v2(&bundle).unwrap(),
            availability_context: [0; 32],
            availability_receipt_root: [59; 32],
            availability_bundle_len: u32::try_from(bundle.len()).unwrap(),
            availability_receipt_bitmap: 0b0_00111,
            source_authorization_commitment,
            signature: Signature64([0; 64]),
        };
        marker.availability_context = marker.expected_availability_context();
        let (receipt_root, receipt_bitmap) =
            canonical_bond_inbox_custody_receipts_v2(&marker, &receipts).unwrap();
        marker.availability_receipt_root = receipt_root;
        marker.availability_receipt_bitmap = receipt_bitmap;
        marker = marker.sign(&signer_secret).unwrap();
        for receipt in &receipts {
            assert_ne!(
                bond_inbox_custody_receipt_binding_digest_v2(&marker, receipt.custodian_index,)
                    .unwrap(),
                [0; 32]
            );
        }

        let marker_payload = marker
            .payload_bytes(MAX_BOND_INBOX_BUNDLE_BYTES_V2)
            .unwrap();
        let mut marker_script = vec![opcodes::all::OP_RETURN.into_u8()];
        marker_script.push(opcodes::all::OP_PUSHDATA2.into_u8());
        marker_script
            .extend_from_slice(&u16::try_from(marker_payload.len()).unwrap().to_le_bytes());
        marker_script.extend_from_slice(&marker_payload);
        let mut input = transition_input(60);
        input.witness.script_witness.push(vec![0x33; 64]);
        input
            .witness
            .script_witness
            .push(bond_inbox_source_annex_v2(&bundle, &receipts).unwrap());
        let transaction = Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![input],
            output: vec![
                staging,
                TxOut {
                    asset: Asset::Explicit(AssetId::from_byte_array(
                        configuration.base.policy_asset_id,
                    )),
                    value: Value::Explicit(0),
                    nonce: Nonce::Null,
                    script_pubkey: Script::from(marker_script),
                    witness: Default::default(),
                },
            ],
        };
        let source_transaction = encode::serialize(&transaction);
        let witness = elements_transaction_witness_bytes_v2(&source_transaction).unwrap();
        let entry = BondInboxEntryV2 {
            version: BondInboxEntryV2::VERSION,
            index: 0,
            previous_root: [61; 32],
            observed_sidechain_height: 10,
            observed_parent_height: 1_000,
            source_block_hash: [62; 32],
            source_txid: transaction.txid().to_byte_array(),
            source_wtxid: transaction.wtxid().to_byte_array(),
            source_transaction_len: u32::try_from(source_transaction.len()).unwrap(),
            source_witness_sha256: bond_inbox_source_witness_sha256_v2(&witness).unwrap(),
            source_witness_len: u32::try_from(witness.len()).unwrap(),
            source_tx_index: 0,
            marker_vout: 1,
            marker,
        };
        entry
            .validate(
                configuration.base.availability,
                configuration.bond_inbox_max_bundle_bytes,
                configuration.bond_inbox_refund_minimum_parent_blocks,
            )
            .unwrap();
        BondInboxSourceFixtureV2 {
            configuration,
            entry,
            source_transaction,
            bundle,
            receipts,
        }
    }

    fn successor_bond_inbox_source_transaction_fixture_v2() -> SuccessorBondInboxSourceFixtureV2 {
        let custodian_secrets = (1u8..=5)
            .map(|index| {
                ecx_witness_availability::CustodianSecrets::new(
                    index,
                    [index; 32],
                    [index + 10; 32],
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let custodian_public = custodian_secrets
            .iter()
            .map(ecx_witness_availability::CustodianSecrets::public)
            .collect::<Vec<_>>();
        let mut configuration = bond_inbox_source_test_configuration_v2();
        // Bind this cross-language node vector to the exact policy asset of
        // the private Elements regtest chain used by the actual-node suite.
        // AssetId parsing performs the display/internal-byte conversion, so
        // the canonical configuration and wire transaction match Elements.
        configuration.base.policy_asset_id =
            AssetId::from_str("b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23")
                .unwrap()
                .into_inner()
                .to_byte_array();
        configuration.base.availability.custodian_registry_hash =
            ecx_witness_availability::custodian_registry_hash(&custodian_public).unwrap();
        configuration.validate().unwrap();
        let signer_secret = SecretKey::from_slice(&[54; 32]).unwrap();
        let signer_keypair =
            elements::secp256k1_zkp::Keypair::from_secret_key(&Secp256k1::new(), &signer_secret);
        let (signer, _) = elements::secp256k1_zkp::XOnlyPublicKey::from_keypair(&signer_keypair);
        let staging_intent_id = [75; 32];
        let refund_script_sha256 = [76; 32];
        let refund_not_before_parent_height = 1_012;
        let staging_vout = 0;
        let renderer_input = BondInboxRedemptionStagingRendererInputV2 {
            chain_id: configuration.base.chain_id,
            configuration_hash: configuration.digest(),
            marker_signer: XOnlyKey(signer.serialize()),
            stable_intent_id: staging_intent_id,
            staging_vout,
            refund_script_sha256,
            refund_not_before_parent_height,
        };
        let staging = confidential_test_txout_v2(
            &configuration,
            renderer_input,
            configuration.bond_asset_id,
            400,
        );
        let source_authorization_commitment =
            successor_bond_inbox_staging_source_authorization_commitment_v2(
                &encode::serialize(&staging),
                staging_intent_id,
                refund_script_sha256,
                refund_not_before_parent_height,
            )
            .unwrap();
        let mut marker = SuccessorBondInboxMarkerV2 {
            version: SUCCESSOR_BOND_INBOX_MARKER_VERSION_V2,
            kind: BondInboxActionKindV2::RedemptionEnqueue,
            chain_id: configuration.base.chain_id,
            configuration_hash: configuration.digest(),
            signer: XOnlyKey(signer.serialize()),
            action_id: [77; 32],
            staging_intent_id,
            staging_vout,
            refund_script_sha256,
            refund_not_before_parent_height,
            payload_commitment: [78; 32],
            availability_scheme_hash: configuration.base.availability.scheme_hash,
            availability_custodian_registry_hash: configuration
                .base
                .availability
                .custodian_registry_hash,
            availability_bundle_root: [1; 32],
            availability_context: [0; 32],
            availability_receipt_root: [79; 32],
            availability_bundle_len: 1,
            availability_receipt_bitmap: 0b0_00111,
            source_authorization_commitment,
            signature: Signature64([0; 64]),
        };
        marker.availability_context = marker.expected_availability_context();
        let encrypted_bundle = ecx_witness_availability::create_bundle(
            marker.availability_context,
            &[0x81; 128],
            &custodian_public,
        )
        .unwrap();
        let bundle = encrypted_bundle.encode().unwrap();
        marker.availability_bundle_root =
            successor_bond_inbox_availability_bundle_root_v2(&bundle).unwrap();
        marker.availability_bundle_len = u32::try_from(bundle.len()).unwrap();
        let receipts = custodian_secrets[..3]
            .iter()
            .map(|custodian| {
                let receipt = custodian.custody_receipt(&encrypted_bundle).unwrap();
                BondInboxCustodyReceiptV2 {
                    custodian_index: receipt.custodian_index - 1,
                    exact_receipt_bytes: receipt.encode_canonical().unwrap().to_vec(),
                }
            })
            .collect::<Vec<_>>();
        ecx_witness_availability::verify_custody_receipts(
            &encrypted_bundle,
            &receipts
                .iter()
                .map(|receipt| {
                    ecx_witness_availability::CustodyReceiptV1::decode_canonical(
                        &receipt.exact_receipt_bytes,
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let (receipt_root, receipt_bitmap) =
            canonical_successor_bond_inbox_custody_receipts_v2(&marker, &receipts).unwrap();
        marker.availability_receipt_root = receipt_root;
        marker.availability_receipt_bitmap = receipt_bitmap;
        marker = marker.sign(&signer_secret).unwrap();
        for receipt in &receipts {
            assert_ne!(
                successor_bond_inbox_custody_receipt_binding_digest_v2(
                    &marker,
                    receipt.custodian_index,
                )
                .unwrap(),
                [0; 32]
            );
        }

        let marker_payload = marker
            .payload_bytes(MAX_BOND_INBOX_BUNDLE_BYTES_V2)
            .unwrap();
        let mut marker_script = vec![opcodes::all::OP_RETURN.into_u8()];
        marker_script.push(opcodes::all::OP_PUSHDATA2.into_u8());
        marker_script
            .extend_from_slice(&u16::try_from(marker_payload.len()).unwrap().to_le_bytes());
        marker_script.extend_from_slice(&marker_payload);
        let mut input = transition_input(80);
        input.witness.script_witness.push(vec![0x43; 64]);
        input
            .witness
            .script_witness
            .push(bond_inbox_source_annex_v2(&bundle, &receipts).unwrap());
        let transaction = Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![input],
            output: vec![
                staging,
                TxOut {
                    asset: Asset::Explicit(AssetId::from_byte_array(
                        configuration.base.policy_asset_id,
                    )),
                    value: Value::Explicit(0),
                    nonce: Nonce::Null,
                    script_pubkey: Script::from(marker_script),
                    witness: Default::default(),
                },
            ],
        };
        let source_transaction = encode::serialize(&transaction);
        let witness = elements_transaction_witness_bytes_v2(&source_transaction).unwrap();
        let entry = SuccessorBondInboxEntryV2 {
            version: SuccessorBondInboxEntryV2::VERSION,
            index: (u128::from(u64::MAX) + 1) << 32,
            previous_root: [81; 32],
            observed_sidechain_height: 10,
            observed_parent_height: 1_000,
            source_block_hash: [82; 32],
            source_txid: transaction.txid().to_byte_array(),
            source_wtxid: transaction.wtxid().to_byte_array(),
            source_transaction_len: u32::try_from(source_transaction.len()).unwrap(),
            source_witness_sha256: Sha256::digest(&witness).into(),
            source_witness_len: u32::try_from(witness.len()).unwrap(),
            source_tx_index: 0,
            marker_vout: 1,
            marker,
        };
        entry
            .validate(
                configuration.base.availability,
                configuration.bond_inbox_max_bundle_bytes,
                configuration.bond_inbox_refund_minimum_parent_blocks,
            )
            .unwrap();
        SuccessorBondInboxSourceFixtureV2 {
            configuration,
            entry,
            source_transaction,
            bundle,
            receipts,
            custodian_public,
        }
    }

    fn confidential_test_txout_v2(
        configuration: &FrozenConfigurationV2,
        renderer_input: BondInboxRedemptionStagingRendererInputV2,
        asset: Hash32,
        amount: u64,
    ) -> TxOut {
        let mut rng = thread_rng();
        let secp = Secp256k1::new();
        let asset_id = AssetId::from_byte_array(asset);
        let receiver_secret = SecretKey::new(&mut rng);
        let receiver_public = PublicKey::from_secret_key(&secp, &receiver_secret);
        let ephemeral_secret = SecretKey::new(&mut rng);
        TxOut::with_txout_secrets(
            &mut rng,
            &secp,
            bond_inbox_redemption_staging_script_v2(configuration, renderer_input).unwrap(),
            receiver_public,
            ephemeral_secret,
            TxOutSecrets::new(
                asset_id,
                AssetBlindingFactor::from_slice(&[63; 32]).unwrap(),
                amount,
                ValueBlindingFactor::from_slice(&[64; 32]).unwrap(),
            ),
            &[TxOutSecrets::new(
                asset_id,
                AssetBlindingFactor::zero(),
                amount,
                ValueBlindingFactor::zero(),
            )],
        )
        .unwrap()
    }

    fn assert_source_fixture_rejected_v2(
        fixture: &BondInboxSourceFixtureV2,
        transaction: Transaction,
    ) {
        let source_transaction = encode::serialize(&transaction);
        let mut entry = fixture.entry;
        entry.source_txid = transaction.txid().to_byte_array();
        entry.source_wtxid = transaction.wtxid().to_byte_array();
        entry.source_transaction_len = u32::try_from(source_transaction.len()).unwrap();
        let witness = elements_transaction_witness_bytes_v2(&source_transaction).unwrap();
        entry.source_witness_sha256 = bond_inbox_source_witness_sha256_v2(&witness).unwrap();
        entry.source_witness_len = u32::try_from(witness.len()).unwrap();
        assert_eq!(
            verify_bond_inbox_source_transaction_v2(
                &entry,
                &source_transaction,
                &fixture.bundle,
                &fixture.receipts,
                &fixture.configuration,
            ),
            Err(SettlementError::BondInboxSourceMismatch)
        );
    }

    fn assert_successor_source_fixture_rejected_v2(
        fixture: &SuccessorBondInboxSourceFixtureV2,
        transaction: Transaction,
    ) {
        let source_transaction = encode::serialize(&transaction);
        let mut entry = fixture.entry;
        entry.source_txid = transaction.txid().to_byte_array();
        entry.source_wtxid = transaction.wtxid().to_byte_array();
        entry.source_transaction_len = u32::try_from(source_transaction.len()).unwrap();
        let witness = elements_transaction_witness_bytes_v2(&source_transaction).unwrap();
        entry.source_witness_sha256 = Sha256::digest(&witness).into();
        entry.source_witness_len = u32::try_from(witness.len()).unwrap();
        assert_eq!(
            verify_successor_bond_inbox_source_transaction_v2(
                &entry,
                &source_transaction,
                &fixture.bundle,
                &fixture.receipts,
                &fixture.configuration,
            ),
            Err(SettlementError::BondInboxSourceMismatch)
        );
    }

    fn marker_script(payload: Vec<u8>) -> Script {
        let mut bytes = vec![opcodes::all::OP_RETURN.into_u8(), payload.len() as u8];
        bytes.extend_from_slice(&payload);
        Script::from(bytes)
    }

    fn minimal_transaction(output: TxOut, marker_script: Script) -> Transaction {
        Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![],
            output: vec![
                output,
                TxOut {
                    asset: Asset::Explicit(AssetId::from_byte_array([9; 32])),
                    value: Value::Explicit(0),
                    nonce: Nonce::Null,
                    script_pubkey: marker_script,
                    witness: Default::default(),
                },
            ],
        }
    }

    fn event_for(
        transaction: &Transaction,
        output: &TxOut,
        previous_root: Hash32,
        trader: XOnlyKey,
    ) -> DepositEventV1 {
        DepositEventV1 {
            version: 1,
            chain_id: [1; 32],
            index: 0,
            previous_root,
            observed_sidechain_height: 10,
            observed_parent_height: 100,
            source_txid: transaction.txid().to_byte_array(),
            deposit_vout: 0,
            marker_vout: 1,
            output_sha256: output_sha256(output),
            trader,
        }
    }
}
