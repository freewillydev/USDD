//! Recursive child statement for the exact unified confidential settlement.

use bincode::Options;
use ecx_elements_settlement::{
    bond_settlement_action_root_v2, verify_previous_transaction_output_openings_v2,
    verify_successor_transition_settlement_v2_with_authenticated_opened_previous_outputs,
    AuthenticatedOpenedPreviousOutputV2, AuthenticatedPreviousOutputV2, BondInputOpeningV2,
    BondInputRoleV2, BondOutputOpeningV2, BondSettlementActionV2, CollateralInputOpeningV2,
    CollateralInputRoleV2, CollateralOutputOpeningV2, FrozenBondAssetV2,
    PreviousTransactionOutputOpeningV2, SettlementError, TransitionSettlementV2,
    VerifiedTransitionSettlementV2, MAX_ELEMENTS_TRANSACTION_BYTES,
};
use ecx_protocol_core::{
    deposit_batch_root, successor_withdrawal_batch_root_v2, DepositRequest, Hash32,
    SuccessorSignedWithdrawalRequestV2, MAX_TRANSITION_ACTIONS,
};
use ecx_truthcoin_proof::{
    sp1_deferred_proof_marker, ConsensusProofVerificationError, ConsensusProofVerifier,
    DenyAllConsensusProofs,
};
use ecx_witness_availability::{
    custodian_registry_hash, verify_custody_receipts_compact, CustodianPublic, CustodyReceiptV1,
    CUSTODY_RECEIPT_CANONICAL_LEN, RECOVERY_THRESHOLD,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    decode_incremental_previous_transaction_projection_v2,
    decode_incremental_source_transaction_child_projection_v2,
    incremental_staging_source_projection_root_v2, IncrementalCustodianPublicV2,
};

pub const INCREMENTAL_SETTLEMENT_CHILD_VERSION_V2: u8 = 1;
pub const INCREMENTAL_SETTLEMENT_CHILD_PUBLIC_VALUES_VERSION_V2: u32 = 3;
pub const INCREMENTAL_SETTLEMENT_CHILD_PUBLIC_VALUES_LEN_V2: usize = 4 + (10 * 32) + 16 + (20 * 8);
pub const MAX_INCREMENTAL_SETTLEMENT_CHILD_INPUT_BYTES_V2: usize = 16 * 1024 * 1024;
/// The compact table prevents repeated copies of one predecessor transaction,
/// but its unique transactions still share the child's recoverable byte cap.
pub const MAX_INCREMENTAL_SETTLEMENT_PREVIOUS_TRANSACTION_BYTES_V2: usize =
    MAX_INCREMENTAL_SETTLEMENT_CHILD_INPUT_BYTES_V2;
/// V18 permits 64 pending actions and up to 768 KiB of unique source
/// transactions per sidechain block. Since its deadline is in parent heights,
/// 64 distinct sidechain blocks can remain processable at one parent height.
/// This is the superseded raw-source design's reachable size. Staged inputs
/// now use recursively authenticated output projections instead of copying
/// those transactions into the settlement child.
pub const V18_SUPERSEDED_RAW_SETTLEMENT_PREDECESSOR_BYTES_V2: usize =
    (MAX_TRANSITION_ACTIONS as usize * 768 * 1024) + MAX_ELEMENTS_TRANSACTION_BYTES;
const _: () = assert!(
    V18_SUPERSEDED_RAW_SETTLEMENT_PREDECESSOR_BYTES_V2
        > MAX_INCREMENTAL_SETTLEMENT_CHILD_INPUT_BYTES_V2
);
pub const MIN_ELEMENTS_TRANSACTION_COMPONENT_BYTES_V2: usize = 40;
pub const MAX_INCREMENTAL_SETTLEMENT_TRANSACTION_COMPONENTS_V2: usize =
    MAX_ELEMENTS_TRANSACTION_BYTES / MIN_ELEMENTS_TRANSACTION_COMPONENT_BYTES_V2;
pub const MAX_INCREMENTAL_SETTLEMENT_OPENING_BYTES_V2: usize = 256;
pub const MAX_INCREMENTAL_SETTLEMENT_ACTION_BYTES_V2: usize = 512;
/// libsecp256k1-zkp's consensus encodings cap range proofs at 5,134 bytes and
/// surjection proofs at 8,258 bytes. Two CompactSize prefixes add six bytes.
pub const MAX_INCREMENTAL_SETTLEMENT_TXOUT_WITNESS_BYTES_V2: usize = 13_398;
pub const MAX_INCREMENTAL_SETTLEMENT_STAGING_TXOUT_BYTES_V2: usize = 256;
/// Fixed bincode bytes in one recursively verified predecessor receipt,
/// excluding its variable public values. This includes the three canonical
/// custody receipts and all vector length prefixes.
pub const MAX_INCREMENTAL_SETTLEMENT_PREVIOUS_RECEIPT_FIXED_BYTES_V2: usize =
    32 + 8 + (3 * 32) + 8 + 8 + (RECOVERY_THRESHOLD * CUSTODY_RECEIPT_CANONICAL_LEN);
/// A complete recursively projected compact settlement has at most one
/// predecessor receipt header per input and exactly one 140-byte output record
/// per projected input. The transaction component ceiling bounds the sum of
/// inputs and outputs, not each vector independently.
pub const MAX_INCREMENTAL_SETTLEMENT_PREVIOUS_RECEIPTS_BYTES_V2: usize =
    MAX_INCREMENTAL_SETTLEMENT_TRANSACTION_COMPONENTS_V2
        * (crate::INCREMENTAL_PREVIOUS_TRANSACTION_PROJECTION_HEADER_BYTES_V2
            + MAX_INCREMENTAL_SETTLEMENT_PREVIOUS_RECEIPT_FIXED_BYTES_V2
            + crate::INCREMENTAL_PREVIOUS_TRANSACTION_OUTPUT_PROJECTION_BYTES_V2);
pub const MAX_INCREMENTAL_SETTLEMENT_STAGING_PROJECTIONS_BYTES_V2: usize = MAX_TRANSITION_ACTIONS
    as usize
    * (crate::INCREMENTAL_SOURCE_TRANSACTION_CHILD_PUBLIC_VALUES_LEN_V2
        + MAX_INCREMENTAL_SETTLEMENT_STAGING_TXOUT_BYTES_V2
        + MAX_INCREMENTAL_SETTLEMENT_TXOUT_WITNESS_BYTES_V2
        + 24);
/// Conservative full parent-witness ceiling for the production compact path:
/// current transaction, every input/output opening, all recursive predecessor
/// receipts, all staged projections, actions/withdrawals, and framing/config.
pub const INCREMENTAL_SETTLEMENT_COMPACT_REACHABLE_CEILING_V2: usize =
    MAX_ELEMENTS_TRANSACTION_BYTES
        + MAX_INCREMENTAL_SETTLEMENT_TRANSACTION_COMPONENTS_V2
            * MAX_INCREMENTAL_SETTLEMENT_OPENING_BYTES_V2
        + MAX_INCREMENTAL_SETTLEMENT_PREVIOUS_RECEIPTS_BYTES_V2
        + MAX_INCREMENTAL_SETTLEMENT_STAGING_PROJECTIONS_BYTES_V2
        + (2 * MAX_TRANSITION_ACTIONS as usize * MAX_INCREMENTAL_SETTLEMENT_ACTION_BYTES_V2)
        + (512 * 1024);
const _: () = assert!(
    INCREMENTAL_SETTLEMENT_COMPACT_REACHABLE_CEILING_V2
        < MAX_INCREMENTAL_SETTLEMENT_CHILD_INPUT_BYTES_V2
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalSettlementChildConfigurationV2 {
    pub version: u8,
    pub usdd_asset_id: Hash32,
    pub collateral_vault_script_sha256: Hash32,
    pub insurance_reserve_script_sha256: Hash32,
    pub frozen_bond_asset: FrozenBondAssetV2,
    pub previous_transaction_program_id: Hash32,
    pub previous_transaction_custodian_registry_hash: Hash32,
}

impl IncrementalSettlementChildConfigurationV2 {
    pub fn validate(self) -> Result<(), IncrementalSettlementChildErrorV2> {
        self.frozen_bond_asset.validate()?;
        let values = [
            self.usdd_asset_id,
            self.collateral_vault_script_sha256,
            self.insurance_reserve_script_sha256,
            self.frozen_bond_asset.asset_id,
            self.frozen_bond_asset.inventory_vault_script_sha256,
            self.frozen_bond_asset.redemption_queue_script_sha256,
            self.frozen_bond_asset.reissuance_token_burn_script_sha256,
            self.previous_transaction_program_id,
            self.previous_transaction_custodian_registry_hash,
        ];
        if self.version != INCREMENTAL_SETTLEMENT_CHILD_VERSION_V2 || values.contains(&[0; 32]) {
            return Err(IncrementalSettlementChildErrorV2::InvalidConfiguration);
        }
        for (index, value) in values.iter().enumerate() {
            if values[..index].contains(value) {
                return Err(IncrementalSettlementChildErrorV2::InvalidConfiguration);
            }
        }
        Ok(())
    }

    pub fn digest(self) -> Result<Hash32, IncrementalSettlementChildErrorV2> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(289);
        bytes.push(self.version);
        for value in [
            self.usdd_asset_id,
            self.collateral_vault_script_sha256,
            self.insurance_reserve_script_sha256,
            self.frozen_bond_asset.asset_id,
            self.frozen_bond_asset.inventory_vault_script_sha256,
            self.frozen_bond_asset.redemption_queue_script_sha256,
            self.frozen_bond_asset.reissuance_token_burn_script_sha256,
            self.previous_transaction_program_id,
            self.previous_transaction_custodian_registry_hash,
        ] {
            bytes.extend_from_slice(&value);
        }
        Ok(tagged_hash(
            b"ECX/incremental-settlement-child-configuration/v1",
            &bytes,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalCollateralInputOpeningV2 {
    pub input_index: u32,
    pub previous_transaction_index: Option<u16>,
    pub authenticated_previous_projection_index: Option<u16>,
    pub previous_vout: u32,
    pub amount: u64,
    pub asset_blinding_factor: [u8; 32],
    pub value_blinding_factor: [u8; 32],
    pub role: CollateralInputRoleV2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalBondInputOpeningV2 {
    pub input_index: u32,
    pub previous_transaction_index: Option<u16>,
    pub authenticated_source_projection_index: Option<u16>,
    pub authenticated_previous_projection_index: Option<u16>,
    pub previous_vout: u32,
    pub amount: u64,
    pub asset_blinding_factor: [u8; 32],
    pub value_blinding_factor: [u8; 32],
    pub role: BondInputRoleV2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalAuthenticatedStagingOutputV2 {
    pub source_public_values: Vec<u8>,
    pub exact_serialized_txout: Vec<u8>,
    pub exact_serialized_txout_witness: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalPreviousTransactionReceiptV2 {
    pub program_id: Hash32,
    pub public_values: Vec<u8>,
    pub proof_marker: Hash32,
    pub bundle_root: Hash32,
    pub bundle_context: Hash32,
    pub child_witness_len: u64,
    pub custody_receipts: Vec<CustodyReceiptV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalTransitionSettlementV2 {
    pub version: u8,
    pub transaction: Vec<u8>,
    pub previous_transactions: Vec<Vec<u8>>,
    pub authenticated_previous_transaction_receipts: Vec<IncrementalPreviousTransactionReceiptV2>,
    pub authenticated_staging_outputs: Vec<IncrementalAuthenticatedStagingOutputV2>,
    pub collateral_inputs: Vec<IncrementalCollateralInputOpeningV2>,
    pub collateral_outputs: Vec<CollateralOutputOpeningV2>,
    pub bond_inputs: Vec<IncrementalBondInputOpeningV2>,
    pub bond_outputs: Vec<BondOutputOpeningV2>,
}

type ExpandedIncrementalSettlementV2 = (
    TransitionSettlementV2,
    Vec<AuthenticatedPreviousOutputV2>,
    Vec<AuthenticatedOpenedPreviousOutputV2>,
    Hash32,
    Hash32,
);

impl IncrementalTransitionSettlementV2 {
    pub fn compact(
        source: TransitionSettlementV2,
    ) -> Result<Self, IncrementalSettlementChildErrorV2> {
        let mut previous_transactions = Vec::<Vec<u8>>::new();
        let mut index_for =
            |transaction: Vec<u8>| -> Result<u16, IncrementalSettlementChildErrorV2> {
                if let Some(index) = previous_transactions
                    .iter()
                    .position(|value| value == &transaction)
                {
                    return u16::try_from(index)
                        .map_err(|_| IncrementalSettlementChildErrorV2::InvalidCompactSettlement);
                }
                let index = u16::try_from(previous_transactions.len())
                    .map_err(|_| IncrementalSettlementChildErrorV2::InvalidCompactSettlement)?;
                previous_transactions.push(transaction);
                Ok(index)
            };
        let mut collateral_inputs = Vec::with_capacity(source.collateral_inputs.len());
        for opening in source.collateral_inputs {
            collateral_inputs.push(IncrementalCollateralInputOpeningV2 {
                input_index: opening.input_index,
                previous_transaction_index: Some(index_for(opening.previous_transaction)?),
                authenticated_previous_projection_index: None,
                previous_vout: opening.previous_vout,
                amount: opening.amount,
                asset_blinding_factor: opening.asset_blinding_factor,
                value_blinding_factor: opening.value_blinding_factor,
                role: opening.role,
            });
        }
        let mut bond_inputs = Vec::with_capacity(source.bond_inputs.len());
        for opening in source.bond_inputs {
            bond_inputs.push(IncrementalBondInputOpeningV2 {
                input_index: opening.input_index,
                previous_transaction_index: Some(index_for(opening.previous_transaction)?),
                authenticated_source_projection_index: None,
                authenticated_previous_projection_index: None,
                previous_vout: opening.previous_vout,
                amount: opening.amount,
                asset_blinding_factor: opening.asset_blinding_factor,
                value_blinding_factor: opening.value_blinding_factor,
                role: opening.role,
            });
        }
        Ok(Self {
            version: source.version,
            transaction: source.transaction,
            previous_transactions,
            authenticated_previous_transaction_receipts: vec![],
            authenticated_staging_outputs: vec![],
            collateral_inputs,
            collateral_outputs: source.collateral_outputs,
            bond_inputs,
            bond_outputs: source.bond_outputs,
        })
    }

    pub fn authenticate_opened_input(
        &mut self,
        input_index: u32,
        previous_transaction_receipt: IncrementalPreviousTransactionReceiptV2,
    ) -> Result<(), IncrementalSettlementChildErrorV2> {
        let projection = decode_incremental_previous_transaction_projection_v2(
            &previous_transaction_receipt.public_values,
        )
        .map_err(|_| IncrementalSettlementChildErrorV2::InvalidCompactSettlement)?;
        let projection_index = if let Some(index) = self
            .authenticated_previous_transaction_receipts
            .iter()
            .position(|receipt| receipt == &previous_transaction_receipt)
        {
            u16::try_from(index)
                .map_err(|_| IncrementalSettlementChildErrorV2::InvalidCompactSettlement)?
        } else {
            let index = u16::try_from(self.authenticated_previous_transaction_receipts.len())
                .map_err(|_| IncrementalSettlementChildErrorV2::InvalidCompactSettlement)?;
            self.authenticated_previous_transaction_receipts
                .push(previous_transaction_receipt);
            index
        };
        if let Some(opening) = self
            .collateral_inputs
            .iter_mut()
            .find(|opening| opening.input_index == input_index)
        {
            if opening.authenticated_previous_projection_index.is_some()
                || !projection.outputs.iter().any(|output| {
                    output.previous_vout == opening.previous_vout && output.amount == opening.amount
                })
            {
                return Err(IncrementalSettlementChildErrorV2::InvalidCompactSettlement);
            }
            opening.previous_transaction_index = None;
            opening.authenticated_previous_projection_index = Some(projection_index);
        } else if let Some(opening) = self
            .bond_inputs
            .iter_mut()
            .find(|opening| opening.input_index == input_index)
        {
            if opening.authenticated_previous_projection_index.is_some()
                || opening.authenticated_source_projection_index.is_some()
                || matches!(
                    opening.role,
                    BondInputRoleV2::StagedRedemptionEnqueue { .. }
                )
                || !projection.outputs.iter().any(|output| {
                    output.previous_vout == opening.previous_vout && output.amount == opening.amount
                })
            {
                return Err(IncrementalSettlementChildErrorV2::InvalidCompactSettlement);
            }
            opening.previous_transaction_index = None;
            opening.authenticated_previous_projection_index = Some(projection_index);
        } else {
            return Err(IncrementalSettlementChildErrorV2::InvalidCompactSettlement);
        }
        self.prune_unused_previous_transactions()
    }

    pub fn authenticate_staged_input(
        &mut self,
        input_index: u32,
        source_public_values: Vec<u8>,
        exact_serialized_txout: Vec<u8>,
        exact_serialized_txout_witness: Vec<u8>,
    ) -> Result<(), IncrementalSettlementChildErrorV2> {
        let projection =
            decode_incremental_source_transaction_child_projection_v2(&source_public_values)
                .map_err(|_| IncrementalSettlementChildErrorV2::InvalidCompactSettlement)?;
        let opening = self
            .bond_inputs
            .iter_mut()
            .find(|opening| opening.input_index == input_index)
            .ok_or(IncrementalSettlementChildErrorV2::InvalidCompactSettlement)?;
        let (source_txid, source_vout, staging_script_sha256) = match opening.role {
            BondInputRoleV2::StagedRedemptionEnqueue {
                source_txid,
                source_vout,
                staging_script_sha256,
                ..
            } => (source_txid, source_vout, staging_script_sha256),
            _ => return Err(IncrementalSettlementChildErrorV2::InvalidCompactSettlement),
        };
        let exact_txout_sha256: Hash32 = Sha256::digest(&exact_serialized_txout).into();
        let exact_txout_witness_sha256: Hash32 =
            Sha256::digest(&exact_serialized_txout_witness).into();
        if !projection.staging_present
            || projection.txid != source_txid
            || projection.staging_vout != source_vout
            || projection.staging_txout_sha256 != exact_txout_sha256
            || projection.staging_txout_witness_sha256 != exact_txout_witness_sha256
            || projection.staging_script_sha256 != staging_script_sha256
            || opening.authenticated_source_projection_index.is_some()
            || opening.authenticated_previous_projection_index.is_some()
        {
            return Err(IncrementalSettlementChildErrorV2::InvalidCompactSettlement);
        }
        let projection_index = u16::try_from(self.authenticated_staging_outputs.len())
            .map_err(|_| IncrementalSettlementChildErrorV2::InvalidCompactSettlement)?;
        self.authenticated_staging_outputs
            .push(IncrementalAuthenticatedStagingOutputV2 {
                source_public_values,
                exact_serialized_txout,
                exact_serialized_txout_witness,
            });
        opening.previous_transaction_index = None;
        opening.authenticated_source_projection_index = Some(projection_index);
        self.prune_unused_previous_transactions()
    }

    fn prune_unused_previous_transactions(
        &mut self,
    ) -> Result<(), IncrementalSettlementChildErrorV2> {
        let mut used = vec![false; self.previous_transactions.len()];
        for index in self
            .collateral_inputs
            .iter()
            .filter_map(|opening| opening.previous_transaction_index)
            .chain(
                self.bond_inputs
                    .iter()
                    .filter_map(|opening| opening.previous_transaction_index),
            )
        {
            *used
                .get_mut(usize::from(index))
                .ok_or(IncrementalSettlementChildErrorV2::InvalidCompactSettlement)? = true;
        }
        let mut remap = vec![None; used.len()];
        let mut retained = Vec::new();
        for (index, transaction) in self.previous_transactions.drain(..).enumerate() {
            if used[index] {
                let next = u16::try_from(retained.len())
                    .map_err(|_| IncrementalSettlementChildErrorV2::InvalidCompactSettlement)?;
                remap[index] = Some(next);
                retained.push(transaction);
            }
        }
        for opening in &mut self.collateral_inputs {
            if let Some(index) = opening.previous_transaction_index {
                opening.previous_transaction_index = Some(
                    remap
                        .get(usize::from(index))
                        .and_then(|value| *value)
                        .ok_or(IncrementalSettlementChildErrorV2::InvalidCompactSettlement)?,
                );
            }
        }
        for opening in &mut self.bond_inputs {
            if let Some(index) = opening.previous_transaction_index {
                opening.previous_transaction_index = Some(
                    remap
                        .get(usize::from(index))
                        .and_then(|value| *value)
                        .ok_or(IncrementalSettlementChildErrorV2::InvalidCompactSettlement)?,
                );
            }
        }
        self.previous_transactions = retained;
        Ok(())
    }

    fn expand(&self) -> Result<ExpandedIncrementalSettlementV2, IncrementalSettlementChildErrorV2> {
        let has_previous_references = !self.collateral_inputs.is_empty()
            && self
                .collateral_inputs
                .iter()
                .any(|opening| opening.previous_transaction_index.is_some())
            || self
                .bond_inputs
                .iter()
                .any(|opening| opening.previous_transaction_index.is_some());
        if self.transaction.is_empty()
            || self.transaction.len() > MAX_ELEMENTS_TRANSACTION_BYTES
            || self.previous_transactions.is_empty() == has_previous_references
            || self.previous_transactions.iter().any(|transaction| {
                transaction.is_empty() || transaction.len() > MAX_ELEMENTS_TRANSACTION_BYTES
            })
        {
            return Err(IncrementalSettlementChildErrorV2::InvalidCompactSettlement);
        }
        let previous_transaction_bytes = self
            .previous_transactions
            .iter()
            .try_fold(0usize, |total, transaction| {
                total.checked_add(transaction.len())
            })
            .ok_or(IncrementalSettlementChildErrorV2::InvalidCompactSettlement)?;
        if previous_transaction_bytes > MAX_INCREMENTAL_SETTLEMENT_PREVIOUS_TRANSACTION_BYTES_V2 {
            return Err(IncrementalSettlementChildErrorV2::InvalidCompactSettlement);
        }
        for (index, transaction) in self.previous_transactions.iter().enumerate() {
            if self.previous_transactions[..index].contains(transaction) {
                return Err(IncrementalSettlementChildErrorV2::InvalidCompactSettlement);
            }
        }
        let source_public_values = self
            .authenticated_staging_outputs
            .iter()
            .map(|output| output.source_public_values.clone())
            .collect::<Vec<_>>();
        let staging_source_projection_root =
            incremental_staging_source_projection_root_v2(&source_public_values)
                .map_err(|_| IncrementalSettlementChildErrorV2::InvalidCompactSettlement)?;
        let mut previous_projection_order = self
            .authenticated_previous_transaction_receipts
            .iter()
            .enumerate()
            .map(|(index, receipt)| {
                decode_incremental_previous_transaction_projection_v2(&receipt.public_values)
                    .map(|projection| (index, &receipt.public_values, projection))
                    .map_err(|_| IncrementalSettlementChildErrorV2::InvalidCompactSettlement)
            })
            .collect::<Result<Vec<_>, _>>()?;
        previous_projection_order.sort_by_key(|(_, _, projection)| projection.txid);
        if previous_projection_order
            .windows(2)
            .any(|window| window[0].2.txid >= window[1].2.txid)
        {
            return Err(IncrementalSettlementChildErrorV2::InvalidCompactSettlement);
        }
        let previous_transaction_projection_root =
            incremental_previous_transaction_projection_root_v2(
                &previous_projection_order
                    .iter()
                    .map(|(_, values, _)| (*values).clone())
                    .collect::<Vec<_>>(),
            )?;
        let previous_projections = self
            .authenticated_previous_transaction_receipts
            .iter()
            .map(|receipt| {
                decode_incremental_previous_transaction_projection_v2(&receipt.public_values)
                    .map_err(|_| IncrementalSettlementChildErrorV2::InvalidCompactSettlement)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut used_previous_projection_outputs = std::collections::BTreeSet::new();
        let mut authenticated_opened_outputs = Vec::new();
        let mut authenticated_outputs =
            Vec::with_capacity(self.authenticated_staging_outputs.len());
        let mut authenticated_projection_used =
            vec![false; self.authenticated_staging_outputs.len()];
        let mut authenticated_projections =
            Vec::with_capacity(self.authenticated_staging_outputs.len());
        for output in &self.authenticated_staging_outputs {
            let projection = decode_incremental_source_transaction_child_projection_v2(
                &output.source_public_values,
            )
            .map_err(|_| IncrementalSettlementChildErrorV2::InvalidCompactSettlement)?;
            let exact_txout_sha256: Hash32 = Sha256::digest(&output.exact_serialized_txout).into();
            let exact_txout_witness_sha256: Hash32 =
                Sha256::digest(&output.exact_serialized_txout_witness).into();
            if output.exact_serialized_txout.is_empty()
                || projection.staging_txout_sha256 != exact_txout_sha256
                || output.exact_serialized_txout_witness.is_empty()
                || projection.staging_txout_witness_sha256 != exact_txout_witness_sha256
            {
                return Err(IncrementalSettlementChildErrorV2::InvalidCompactSettlement);
            }
            authenticated_projections.push(projection);
        }
        let mut used = vec![false; self.previous_transactions.len()];
        let mut previous = |index: u16| -> Result<Vec<u8>, IncrementalSettlementChildErrorV2> {
            let index = usize::from(index);
            let transaction = self
                .previous_transactions
                .get(index)
                .ok_or(IncrementalSettlementChildErrorV2::InvalidCompactSettlement)?;
            used[index] = true;
            Ok(transaction.clone())
        };
        let mut collateral_inputs = Vec::with_capacity(self.collateral_inputs.len());
        for opening in &self.collateral_inputs {
            let previous_transaction = match (
                opening.previous_transaction_index,
                opening.authenticated_previous_projection_index,
            ) {
                (Some(index), None) => previous(index)?,
                (None, Some(index)) => {
                    let index = usize::from(index);
                    let projection = previous_projections
                        .get(index)
                        .ok_or(IncrementalSettlementChildErrorV2::InvalidCompactSettlement)?;
                    let output = projection
                        .outputs
                        .iter()
                        .find(|output| {
                            output.previous_vout == opening.previous_vout
                                && output.amount == opening.amount
                        })
                        .ok_or(IncrementalSettlementChildErrorV2::InvalidCompactSettlement)?;
                    if !used_previous_projection_outputs.insert((index, output.previous_vout)) {
                        return Err(IncrementalSettlementChildErrorV2::InvalidCompactSettlement);
                    }
                    authenticated_opened_outputs.push(AuthenticatedOpenedPreviousOutputV2 {
                        input_index: opening.input_index,
                        previous_txid: projection.txid,
                        previous_vout: output.previous_vout,
                        expected_asset_id: output.expected_asset_id,
                        amount: output.amount,
                        script_sha256: output.script_sha256,
                        txout_sha256: output.txout_sha256,
                        txout_witness_sha256: output.txout_witness_sha256,
                    });
                    Vec::new()
                }
                _ => return Err(IncrementalSettlementChildErrorV2::InvalidCompactSettlement),
            };
            collateral_inputs.push(CollateralInputOpeningV2 {
                input_index: opening.input_index,
                previous_transaction,
                previous_vout: opening.previous_vout,
                amount: opening.amount,
                asset_blinding_factor: opening.asset_blinding_factor,
                value_blinding_factor: opening.value_blinding_factor,
                role: opening.role,
            });
        }
        let mut bond_inputs = Vec::with_capacity(self.bond_inputs.len());
        for opening in &self.bond_inputs {
            let (previous_transaction, authenticated_projection) = match (
                opening.previous_transaction_index,
                opening.authenticated_source_projection_index,
                opening.authenticated_previous_projection_index,
            ) {
                (Some(index), None, None) => (previous(index)?, None),
                (None, Some(index), None) => {
                    let index = usize::from(index);
                    let projection = authenticated_projections
                        .get(index)
                        .ok_or(IncrementalSettlementChildErrorV2::InvalidCompactSettlement)?;
                    let source = self
                        .authenticated_staging_outputs
                        .get(index)
                        .ok_or(IncrementalSettlementChildErrorV2::InvalidCompactSettlement)?;
                    let used = authenticated_projection_used
                        .get_mut(index)
                        .ok_or(IncrementalSettlementChildErrorV2::InvalidCompactSettlement)?;
                    if *used || opening.previous_vout != projection.staging_vout {
                        return Err(IncrementalSettlementChildErrorV2::InvalidCompactSettlement);
                    }
                    *used = true;
                    (Vec::new(), Some((projection, source)))
                }
                (None, None, Some(index)) => {
                    let index = usize::from(index);
                    let projection = previous_projections
                        .get(index)
                        .ok_or(IncrementalSettlementChildErrorV2::InvalidCompactSettlement)?;
                    let output = projection
                        .outputs
                        .iter()
                        .find(|output| {
                            output.previous_vout == opening.previous_vout
                                && output.amount == opening.amount
                        })
                        .ok_or(IncrementalSettlementChildErrorV2::InvalidCompactSettlement)?;
                    if !used_previous_projection_outputs.insert((index, output.previous_vout)) {
                        return Err(IncrementalSettlementChildErrorV2::InvalidCompactSettlement);
                    }
                    authenticated_opened_outputs.push(AuthenticatedOpenedPreviousOutputV2 {
                        input_index: opening.input_index,
                        previous_txid: projection.txid,
                        previous_vout: output.previous_vout,
                        expected_asset_id: output.expected_asset_id,
                        amount: output.amount,
                        script_sha256: output.script_sha256,
                        txout_sha256: output.txout_sha256,
                        txout_witness_sha256: output.txout_witness_sha256,
                    });
                    (Vec::new(), None)
                }
                _ => return Err(IncrementalSettlementChildErrorV2::InvalidCompactSettlement),
            };
            if let Some((projection, source)) = authenticated_projection {
                authenticated_outputs.push(AuthenticatedPreviousOutputV2 {
                    input_index: opening.input_index,
                    previous_txid: projection.txid,
                    previous_vout: projection.staging_vout,
                    exact_serialized_txout: source.exact_serialized_txout.clone(),
                    exact_serialized_txout_witness: source.exact_serialized_txout_witness.clone(),
                });
            }
            bond_inputs.push(BondInputOpeningV2 {
                input_index: opening.input_index,
                previous_transaction,
                previous_vout: opening.previous_vout,
                amount: opening.amount,
                asset_blinding_factor: opening.asset_blinding_factor,
                value_blinding_factor: opening.value_blinding_factor,
                role: opening.role,
            });
        }
        let projected_output_count = previous_projections
            .iter()
            .map(|projection| projection.outputs.len())
            .sum::<usize>();
        if used.contains(&false)
            || authenticated_projection_used.contains(&false)
            || used_previous_projection_outputs.len() != projected_output_count
        {
            return Err(IncrementalSettlementChildErrorV2::InvalidCompactSettlement);
        }
        Ok((
            TransitionSettlementV2 {
                version: self.version,
                transaction: self.transaction.clone(),
                collateral_inputs,
                collateral_outputs: self.collateral_outputs.clone(),
                bond_inputs,
                bond_outputs: self.bond_outputs.clone(),
            },
            authenticated_outputs,
            authenticated_opened_outputs,
            staging_source_projection_root,
            previous_transaction_projection_root,
        ))
    }
}

pub fn incremental_previous_transaction_projection_root_v2(
    ordered_public_values: &[Vec<u8>],
) -> Result<Hash32, IncrementalSettlementChildErrorV2> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(
        &u32::try_from(ordered_public_values.len())
            .map_err(|_| IncrementalSettlementChildErrorV2::InvalidCompactSettlement)?
            .to_be_bytes(),
    );
    let mut previous_txid = None;
    for values in ordered_public_values {
        let projection = decode_incremental_previous_transaction_projection_v2(values)
            .map_err(|_| IncrementalSettlementChildErrorV2::InvalidCompactSettlement)?;
        if previous_txid.is_some_and(|prior| prior >= projection.txid) {
            return Err(IncrementalSettlementChildErrorV2::InvalidCompactSettlement);
        }
        previous_txid = Some(projection.txid);
        bytes.extend_from_slice(&projection.txid);
        bytes.extend_from_slice(&Sha256::digest(values));
    }
    Ok(tagged_hash(
        b"ECX/incremental-previous-transaction-projection-root/v1",
        &bytes,
    ))
}

pub fn incremental_previous_transaction_bundle_context_v2(
    program_id: Hash32,
    public_values: &[u8],
    proof_marker: Hash32,
    registry_hash: Hash32,
) -> Hash32 {
    let mut bytes = Vec::with_capacity(128);
    bytes.extend_from_slice(&program_id);
    bytes.extend_from_slice(&Sha256::digest(public_values));
    bytes.extend_from_slice(&proof_marker);
    bytes.extend_from_slice(&registry_hash);
    tagged_hash(
        b"ECX/incremental-previous-transaction-bundle-context/v1",
        &bytes,
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalSettlementChildInputV2 {
    pub version: u8,
    pub configuration: IncrementalSettlementChildConfigurationV2,
    pub settlement: IncrementalTransitionSettlementV2,
    pub previous_transaction_custodians: Vec<IncrementalCustodianPublicV2>,
    pub deposits: Vec<DepositRequest>,
    /// Successor forced-inbox cursor authenticated by the forced-action child.
    /// The historical ECXC/u64 field in the settlement transaction must be
    /// zero and is not reused as a narrowing successor identity.
    pub successor_forced_processed_cursor: u128,
    pub withdrawals: Vec<SuccessorSignedWithdrawalRequestV2>,
    pub bond_actions: Vec<BondSettlementActionV2>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalSettlementChildPublicValuesV2 {
    pub configuration_hash: Hash32,
    pub transition_txid: Hash32,
    pub action_root: Hash32,
    pub withdrawal_root: Hash32,
    pub deposit_batch_root: Hash32,
    pub staging_source_projection_root: Hash32,
    pub previous_transaction_projection_root: Hash32,
    pub collateral_settlement_root: Hash32,
    pub bond_settlement_root: Hash32,
    pub combined_settlement_root: Hash32,
    pub forced_processed_cursor: u128,
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
}

impl IncrementalSettlementChildPublicValuesV2 {
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(INCREMENTAL_SETTLEMENT_CHILD_PUBLIC_VALUES_LEN_V2);
        out.extend_from_slice(&INCREMENTAL_SETTLEMENT_CHILD_PUBLIC_VALUES_VERSION_V2.to_be_bytes());
        for value in [
            self.configuration_hash,
            self.transition_txid,
            self.action_root,
            self.withdrawal_root,
            self.deposit_batch_root,
            self.staging_source_projection_root,
            self.previous_transaction_projection_root,
            self.collateral_settlement_root,
            self.bond_settlement_root,
            self.combined_settlement_root,
        ] {
            out.extend_from_slice(&value);
        }
        out.extend_from_slice(&self.forced_processed_cursor.to_be_bytes());
        for value in [
            self.deposit_processed_cursor,
            self.collateral_input_total,
            self.collateral_output_total,
            self.collateral_vault_input_total,
            self.insurance_reserve_input_total,
            self.collateral_vault_change_total,
            self.insurance_reserve_output_total,
            self.subscription_contribution_total,
            self.recapitalization_contribution_total,
            self.redemption_payment_total,
            self.withdrawal_total,
            self.bond_input_total,
            self.bond_output_total,
            self.bond_inventory_input_total,
            self.bond_inventory_change_total,
            self.bond_subscription_total,
            self.queued_redemption_input_total,
            self.redemption_remainder_total,
            self.redemption_inventory_return_total,
            self.rejected_enqueue_refund_total,
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        debug_assert_eq!(out.len(), INCREMENTAL_SETTLEMENT_CHILD_PUBLIC_VALUES_LEN_V2);
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalSettlementChildProjectionV2 {
    pub configuration_hash: Hash32,
    pub transition_txid: Hash32,
    pub action_root: Hash32,
    pub withdrawal_root: Hash32,
    pub deposit_batch_root: Hash32,
    pub staging_source_projection_root: Hash32,
    pub previous_transaction_projection_root: Hash32,
    pub combined_settlement_root: Hash32,
    pub forced_processed_cursor: u128,
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
}

pub fn decode_incremental_settlement_child_projection_v2(
    bytes: &[u8],
) -> Result<IncrementalSettlementChildProjectionV2, IncrementalSettlementChildErrorV2> {
    if bytes.len() != INCREMENTAL_SETTLEMENT_CHILD_PUBLIC_VALUES_LEN_V2
        || bytes[..4] != INCREMENTAL_SETTLEMENT_CHILD_PUBLIC_VALUES_VERSION_V2.to_be_bytes()
    {
        return Err(IncrementalSettlementChildErrorV2::UnsupportedVersion);
    }
    let hash = |start: usize| -> Result<Hash32, IncrementalSettlementChildErrorV2> {
        bytes[start..start + 32]
            .try_into()
            .map_err(|_| IncrementalSettlementChildErrorV2::UnsupportedVersion)
    };
    let forced_processed_cursor = u128::from_be_bytes(
        bytes[4 + (10 * 32)..4 + (10 * 32) + 16]
            .try_into()
            .map_err(|_| IncrementalSettlementChildErrorV2::UnsupportedVersion)?,
    );
    let amount = |index: usize| -> Result<u64, IncrementalSettlementChildErrorV2> {
        let start = 4 + (10 * 32) + 16 + (index * 8);
        Ok(u64::from_be_bytes(
            bytes[start..start + 8]
                .try_into()
                .map_err(|_| IncrementalSettlementChildErrorV2::UnsupportedVersion)?,
        ))
    };
    Ok(IncrementalSettlementChildProjectionV2 {
        configuration_hash: hash(4)?,
        transition_txid: hash(4 + 32)?,
        action_root: hash(4 + (2 * 32))?,
        withdrawal_root: hash(4 + (3 * 32))?,
        deposit_batch_root: hash(4 + (4 * 32))?,
        staging_source_projection_root: hash(4 + (5 * 32))?,
        previous_transaction_projection_root: hash(4 + (6 * 32))?,
        combined_settlement_root: hash(4 + (9 * 32))?,
        forced_processed_cursor,
        deposit_processed_cursor: amount(0)?,
        collateral_input_total: amount(1)?,
        collateral_output_total: amount(2)?,
        collateral_vault_input_total: amount(3)?,
        insurance_reserve_input_total: amount(4)?,
        collateral_vault_change_total: amount(5)?,
        insurance_reserve_output_total: amount(6)?,
        subscription_contribution_total: amount(7)?,
        recapitalization_contribution_total: amount(8)?,
        redemption_payment_total: amount(9)?,
        withdrawal_total: amount(10)?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IncrementalSettlementChildErrorV2 {
    #[error("invalid incremental settlement child configuration")]
    InvalidConfiguration,
    #[error("unsupported incremental settlement child version")]
    UnsupportedVersion,
    #[error("invalid compact incremental settlement witness")]
    InvalidCompactSettlement,
    #[error("incremental settlement child input exceeds its recovery cap")]
    InputTooLarge,
    #[error("incremental settlement child input encoding failed")]
    InputEncoding,
    #[error("invalid recursive predecessor-transaction proof or availability")]
    InvalidPreviousTransactionProof,
    #[error("unified settlement rejected: {0}")]
    Settlement(#[from] SettlementError),
}

fn tagged_hash(tag: &[u8], bytes: &[u8]) -> Hash32 {
    let tag_hash: Hash32 = Sha256::digest(tag).into();
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(bytes);
    hasher.finalize().into()
}

#[allow(clippy::too_many_arguments)]
fn public_values(
    configuration_hash: Hash32,
    action_root: Hash32,
    withdrawal_root: Hash32,
    deposit_root: Hash32,
    staging_source_projection_root: Hash32,
    previous_transaction_projection_root: Hash32,
    successor_forced_processed_cursor: u128,
    verified: VerifiedTransitionSettlementV2,
) -> IncrementalSettlementChildPublicValuesV2 {
    IncrementalSettlementChildPublicValuesV2 {
        configuration_hash,
        transition_txid: verified.transition_txid,
        action_root,
        withdrawal_root,
        deposit_batch_root: deposit_root,
        staging_source_projection_root,
        previous_transaction_projection_root,
        collateral_settlement_root: verified.collateral_settlement_root,
        bond_settlement_root: verified.bond_settlement_root,
        combined_settlement_root: verified.combined_settlement_root,
        forced_processed_cursor: successor_forced_processed_cursor,
        deposit_processed_cursor: verified.deposit_processed_cursor,
        collateral_input_total: verified.collateral_input_total,
        collateral_output_total: verified.collateral_output_total,
        collateral_vault_input_total: verified.collateral_vault_input_total,
        insurance_reserve_input_total: verified.insurance_reserve_input_total,
        collateral_vault_change_total: verified.collateral_vault_change_total,
        insurance_reserve_output_total: verified.insurance_reserve_output_total,
        subscription_contribution_total: verified.subscription_contribution_total,
        recapitalization_contribution_total: verified.recapitalization_contribution_total,
        redemption_payment_total: verified.redemption_payment_total,
        withdrawal_total: verified.withdrawal_total,
        bond_input_total: verified.bond_input_total,
        bond_output_total: verified.bond_output_total,
        bond_inventory_input_total: verified.bond_inventory_input_total,
        bond_inventory_change_total: verified.bond_inventory_change_total,
        bond_subscription_total: verified.bond_subscription_total,
        queued_redemption_input_total: verified.queued_redemption_input_total,
        redemption_remainder_total: verified.redemption_remainder_total,
        redemption_inventory_return_total: verified.redemption_inventory_return_total,
        rejected_enqueue_refund_total: verified.rejected_enqueue_refund_total,
    }
}

fn verify_declared_deposit_inputs(
    settlement: &TransitionSettlementV2,
    deposits: &[DepositRequest],
    expected_usdd_asset_id: Hash32,
) -> Result<(), IncrementalSettlementChildErrorV2> {
    let mut seen = std::collections::BTreeSet::new();
    for deposit in deposits {
        deposit
            .validate()
            .map_err(|_| IncrementalSettlementChildErrorV2::InvalidCompactSettlement)?;
        if deposit.usdd_asset_id != expected_usdd_asset_id {
            return Err(IncrementalSettlementChildErrorV2::InvalidCompactSettlement);
        }
        if !seen.insert((deposit.deposit_txid, deposit.deposit_vout)) {
            return Err(IncrementalSettlementChildErrorV2::InvalidCompactSettlement);
        }
        let matches = settlement
            .collateral_inputs
            .iter()
            .filter(|opening| {
                if opening.role != CollateralInputRoleV2::CollateralVault
                    || opening.previous_vout != deposit.deposit_vout
                    || opening.amount != deposit.amount
                {
                    return false;
                }
                verify_previous_transaction_output_openings_v2(
                    &opening.previous_transaction,
                    &[PreviousTransactionOutputOpeningV2 {
                        previous_vout: opening.previous_vout,
                        expected_asset_id: deposit.usdd_asset_id,
                        amount: opening.amount,
                        asset_blinding_factor: opening.asset_blinding_factor,
                        value_blinding_factor: opening.value_blinding_factor,
                    }],
                )
                .map(|transaction| transaction.txid == deposit.deposit_txid)
                .unwrap_or(false)
            })
            .count();
        if matches != 1 {
            return Err(IncrementalSettlementChildErrorV2::InvalidCompactSettlement);
        }
    }
    Ok(())
}

pub fn execute_incremental_settlement_child_v2(
    input: &IncrementalSettlementChildInputV2,
) -> Result<IncrementalSettlementChildPublicValuesV2, IncrementalSettlementChildErrorV2> {
    execute_incremental_settlement_child_v2_with_consensus_verifier(input, &DenyAllConsensusProofs)
}

pub fn execute_incremental_settlement_child_v2_with_consensus_verifier<
    V: ConsensusProofVerifier,
>(
    input: &IncrementalSettlementChildInputV2,
    verifier: &V,
) -> Result<IncrementalSettlementChildPublicValuesV2, IncrementalSettlementChildErrorV2> {
    if input.version != INCREMENTAL_SETTLEMENT_CHILD_VERSION_V2 {
        return Err(IncrementalSettlementChildErrorV2::UnsupportedVersion);
    }
    input.configuration.validate()?;
    let encoded = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .serialize(input)
        .map_err(|_| IncrementalSettlementChildErrorV2::InputEncoding)?;
    if encoded.len() > MAX_INCREMENTAL_SETTLEMENT_CHILD_INPUT_BYTES_V2
        || input.withdrawals.len() > MAX_TRANSITION_ACTIONS as usize
        || input.bond_actions.len() > MAX_TRANSITION_ACTIONS as usize
    {
        return Err(IncrementalSettlementChildErrorV2::InputTooLarge);
    }
    let custodians = input
        .previous_transaction_custodians
        .iter()
        .copied()
        .map(CustodianPublic::from)
        .collect::<Vec<_>>();
    let receipts = &input.settlement.authenticated_previous_transaction_receipts;
    if receipts.is_empty() {
        if !custodians.is_empty() {
            return Err(IncrementalSettlementChildErrorV2::InvalidPreviousTransactionProof);
        }
    } else if custodians.len() != 5
        || custodian_registry_hash(&custodians)
            .map_err(|_| IncrementalSettlementChildErrorV2::InvalidPreviousTransactionProof)?
            != input
                .configuration
                .previous_transaction_custodian_registry_hash
    {
        return Err(IncrementalSettlementChildErrorV2::InvalidPreviousTransactionProof);
    }
    for receipt in receipts {
        if receipt.program_id != input.configuration.previous_transaction_program_id
            || receipt.proof_marker
                != sp1_deferred_proof_marker(receipt.program_id, &receipt.public_values)
            || receipt.custody_receipts.len() != RECOVERY_THRESHOLD
            || receipt.bundle_context
                != incremental_previous_transaction_bundle_context_v2(
                    receipt.program_id,
                    &receipt.public_values,
                    receipt.proof_marker,
                    input
                        .configuration
                        .previous_transaction_custodian_registry_hash,
                )
        {
            return Err(IncrementalSettlementChildErrorV2::InvalidPreviousTransactionProof);
        }
        verifier
            .verify(
                receipt.program_id,
                &receipt.public_values,
                &receipt.proof_marker,
            )
            .map_err(|_: ConsensusProofVerificationError| {
                IncrementalSettlementChildErrorV2::InvalidPreviousTransactionProof
            })?;
        verify_custody_receipts_compact(
            receipt.bundle_root,
            receipt.bundle_context,
            receipt.child_witness_len,
            &custodians,
            &receipt.custody_receipts,
        )
        .map_err(|_| IncrementalSettlementChildErrorV2::InvalidPreviousTransactionProof)?;
    }
    let (
        settlement,
        authenticated_previous_outputs,
        authenticated_opened_previous_outputs,
        staging_source_projection_root,
        previous_transaction_projection_root,
    ) = input.settlement.expand()?;
    if input.deposits.len() > MAX_TRANSITION_ACTIONS as usize {
        return Err(IncrementalSettlementChildErrorV2::InvalidCompactSettlement);
    }
    verify_declared_deposit_inputs(
        &settlement,
        &input.deposits,
        input.configuration.usdd_asset_id,
    )?;
    let verified =
        verify_successor_transition_settlement_v2_with_authenticated_opened_previous_outputs(
            &settlement,
            &input.withdrawals,
            &input.bond_actions,
            input.configuration.usdd_asset_id,
            input.configuration.collateral_vault_script_sha256,
            input.configuration.insurance_reserve_script_sha256,
            &input.configuration.frozen_bond_asset,
            &authenticated_previous_outputs,
            &authenticated_opened_previous_outputs,
        )?;
    if verified.forced_processed_cursor != 0 {
        return Err(IncrementalSettlementChildErrorV2::InvalidCompactSettlement);
    }
    Ok(public_values(
        input.configuration.digest()?,
        bond_settlement_action_root_v2(&input.bond_actions),
        successor_withdrawal_batch_root_v2(&input.withdrawals),
        deposit_batch_root(&input.deposits),
        staging_source_projection_root,
        previous_transaction_projection_root,
        input.successor_forced_processed_cursor,
        verified,
    ))
}

#[cfg(test)]
mod tests {
    use ecx_elements_settlement::{BondOutputRoleV2, CollateralOutputRoleV2};
    use ecx_protocol_core::{
        Signature64, SuccessorSignedWithdrawalRequestV2, SuccessorWithdrawalRequestV2, XOnlyKey,
    };
    use ecx_truthcoin_proof::ConsensusProofVerificationError;
    use ecx_witness_availability::{create_bundle, CustodianSecrets};
    use elements::{
        confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor},
        encode,
        hashes::Hash,
        opcodes,
        secp256k1_zkp::{PublicKey, Secp256k1, SecretKey},
        AssetId, LockTime, OutPoint, Script, Transaction, TxIn, TxOut, TxOutSecrets,
    };
    use rand::thread_rng;

    use super::*;

    struct MarkerVerifier;

    impl ConsensusProofVerifier for MarkerVerifier {
        fn verify(
            &self,
            program_id: Hash32,
            public_values: &[u8],
            proof_marker: &[u8],
        ) -> Result<(), ConsensusProofVerificationError> {
            if proof_marker == sp1_deferred_proof_marker(program_id, public_values) {
                Ok(())
            } else {
                Err(ConsensusProofVerificationError)
            }
        }
    }

    fn configuration() -> IncrementalSettlementChildConfigurationV2 {
        IncrementalSettlementChildConfigurationV2 {
            version: INCREMENTAL_SETTLEMENT_CHILD_VERSION_V2,
            usdd_asset_id: [1; 32],
            collateral_vault_script_sha256: [2; 32],
            insurance_reserve_script_sha256: [3; 32],
            frozen_bond_asset: FrozenBondAssetV2 {
                version: FrozenBondAssetV2::VERSION,
                asset_id: [4; 32],
                inventory_vault_script_sha256: [5; 32],
                redemption_queue_script_sha256: [6; 32],
                reissuance_token_burn_script_sha256: [7; 32],
            },
            previous_transaction_program_id: [8; 32],
            previous_transaction_custodian_registry_hash: [9; 32],
        }
    }

    fn explicit_output(asset: Hash32, value: u64, script: Script) -> TxOut {
        TxOut {
            asset: Asset::Explicit(AssetId::from_byte_array(asset)),
            value: Value::Explicit(value),
            nonce: Nonce::Null,
            script_pubkey: script,
            witness: Default::default(),
        }
    }

    fn no_economic_settlement() -> TransitionSettlementV2 {
        let mut payload = b"ECXC".to_vec();
        payload.push(1);
        payload.extend_from_slice(&0u64.to_le_bytes());
        payload.extend_from_slice(&12u64.to_le_bytes());
        let mut marker = vec![opcodes::all::OP_RETURN.into_u8(), 21];
        marker.extend_from_slice(&payload);
        let transaction = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: OutPoint::new(elements::Txid::from_byte_array([8; 32]), 0),
                    ..TxIn::default()
                },
                TxIn {
                    previous_output: OutPoint::new(elements::Txid::from_byte_array([9; 32]), 0),
                    ..TxIn::default()
                },
            ],
            output: vec![
                explicit_output([10; 32], 1, Script::from(vec![0x51])),
                explicit_output([10; 32], 1, Script::from(vec![0x51, 0x51])),
                explicit_output([10; 32], 0, Script::from(marker)),
            ],
        };
        TransitionSettlementV2 {
            version: 2,
            transaction: encode::serialize(&transaction),
            collateral_inputs: vec![],
            collateral_outputs: vec![],
            bond_inputs: vec![],
            bond_outputs: vec![],
        }
    }

    fn fixed_size<T: Serialize>(value: &T) -> usize {
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .serialized_size(value)
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    fn compact_settlement_deduplicates_and_rejects_malformed_transaction_tables() {
        let previous_transaction = vec![9, 8, 7];
        let source = TransitionSettlementV2 {
            version: 2,
            transaction: vec![1],
            collateral_inputs: vec![CollateralInputOpeningV2 {
                input_index: 2,
                previous_transaction: previous_transaction.clone(),
                previous_vout: 0,
                amount: 11,
                asset_blinding_factor: [1; 32],
                value_blinding_factor: [2; 32],
                role: CollateralInputRoleV2::CollateralVault,
            }],
            collateral_outputs: vec![],
            bond_inputs: vec![BondInputOpeningV2 {
                input_index: 3,
                previous_transaction: previous_transaction.clone(),
                previous_vout: 1,
                amount: 12,
                asset_blinding_factor: [3; 32],
                value_blinding_factor: [4; 32],
                role: BondInputRoleV2::InventoryVault,
            }],
            bond_outputs: vec![],
        };
        let compact = IncrementalTransitionSettlementV2::compact(source.clone()).unwrap();
        assert_eq!(compact.previous_transactions, vec![previous_transaction]);
        assert_eq!(
            compact.collateral_inputs[0].previous_transaction_index,
            Some(0)
        );
        assert_eq!(compact.bond_inputs[0].previous_transaction_index, Some(0));
        let (expanded, authenticated, opened, projection_root, previous_root) =
            compact.expand().unwrap();
        assert_eq!(expanded, source);
        assert!(authenticated.is_empty());
        assert!(opened.is_empty());
        assert_eq!(
            projection_root,
            incremental_staging_source_projection_root_v2(&[]).unwrap()
        );
        assert_eq!(
            previous_root,
            incremental_previous_transaction_projection_root_v2(&[]).unwrap()
        );

        let mut duplicate = compact.clone();
        duplicate
            .previous_transactions
            .push(duplicate.previous_transactions[0].clone());
        assert_eq!(
            duplicate.expand().unwrap_err(),
            IncrementalSettlementChildErrorV2::InvalidCompactSettlement
        );

        let mut unused = compact.clone();
        unused.previous_transactions.push(vec![6]);
        assert_eq!(
            unused.expand().unwrap_err(),
            IncrementalSettlementChildErrorV2::InvalidCompactSettlement
        );

        let mut bad_reference = compact;
        bad_reference.bond_inputs[0].previous_transaction_index = Some(1);
        assert_eq!(
            bad_reference.expand().unwrap_err(),
            IncrementalSettlementChildErrorV2::InvalidCompactSettlement
        );
    }

    #[test]
    fn compact_settlement_authenticates_staging_projection_and_prunes_raw_source() {
        let exact_txout = vec![9, 8, 7];
        let source_txid = [21; 32];
        let source_vout = 1;
        let staging_script_sha256 = [22; 32];
        let source = TransitionSettlementV2 {
            version: 2,
            transaction: vec![1],
            collateral_inputs: vec![],
            collateral_outputs: vec![],
            bond_inputs: vec![BondInputOpeningV2 {
                input_index: 2,
                previous_transaction: exact_txout.clone(),
                previous_vout: source_vout,
                amount: 12,
                asset_blinding_factor: [3; 32],
                value_blinding_factor: [4; 32],
                role: BondInputRoleV2::StagedRedemptionEnqueue {
                    redemption_id: [23; 32],
                    staging_intent_id: [24; 32],
                    claimant: [25; 32],
                    staging_script_sha256,
                    source_txid,
                    source_vout,
                },
            }],
            bond_outputs: vec![],
        };
        let source_public_values = crate::IncrementalSourceTransactionChildPublicValuesV2 {
            configuration_hash: [26; 32],
            chain_id: [27; 32],
            entry_hash: [28; 32],
            txid: source_txid,
            wtxid: [29; 32],
            exact_witness_sha256: [30; 32],
            availability_bundle_root: [31; 32],
            availability_receipt_root: [32; 32],
            staging_txout_sha256: Sha256::digest(&exact_txout).into(),
            staging_txout_witness_sha256: Sha256::digest([33]).into(),
            staging_script_sha256,
            source_transaction_len: 100,
            availability_bundle_len: 101,
            staging_vout: source_vout,
            staging_present: true,
        }
        .encode();
        let mut compact = IncrementalTransitionSettlementV2::compact(source).unwrap();
        compact
            .authenticate_staged_input(
                2,
                source_public_values.clone(),
                exact_txout.clone(),
                vec![33],
            )
            .unwrap();
        assert!(compact.previous_transactions.is_empty());
        let (expanded, authenticated, opened, projection_root, previous_root) =
            compact.expand().unwrap();
        assert!(expanded.bond_inputs[0].previous_transaction.is_empty());
        assert_eq!(authenticated[0].previous_txid, source_txid);
        assert!(opened.is_empty());
        assert_eq!(authenticated[0].exact_serialized_txout, exact_txout);
        assert_eq!(
            projection_root,
            incremental_staging_source_projection_root_v2(&[source_public_values]).unwrap()
        );
        assert_eq!(
            previous_root,
            incremental_previous_transaction_projection_root_v2(&[]).unwrap()
        );

        let mut unused = compact;
        unused
            .authenticated_staging_outputs
            .push(unused.authenticated_staging_outputs[0].clone());
        assert_eq!(
            unused.expand().unwrap_err(),
            IncrementalSettlementChildErrorV2::InvalidCompactSettlement
        );
    }

    #[test]
    fn compact_generic_projection_and_recursive_availability_are_exact() {
        let previous_transaction = vec![9, 8, 7];
        let source = TransitionSettlementV2 {
            version: 2,
            transaction: vec![1],
            collateral_inputs: vec![CollateralInputOpeningV2 {
                input_index: 2,
                previous_transaction: previous_transaction.clone(),
                previous_vout: 0,
                amount: 11,
                asset_blinding_factor: [1; 32],
                value_blinding_factor: [2; 32],
                role: CollateralInputRoleV2::CollateralVault,
            }],
            collateral_outputs: vec![],
            bond_inputs: vec![],
            bond_outputs: vec![],
        };
        let public_values = crate::IncrementalPreviousTransactionProjectionV2 {
            txid: [31; 32],
            wtxid: [32; 32],
            transaction_len: 100,
            outputs: vec![crate::IncrementalPreviousTransactionOutputProjectionV2 {
                previous_vout: 0,
                expected_asset_id: configuration().usdd_asset_id,
                amount: 11,
                script_sha256: configuration().collateral_vault_script_sha256,
                txout_sha256: [33; 32],
                txout_witness_sha256: [34; 32],
            }],
        }
        .encode()
        .unwrap();
        let secrets = (1..=5)
            .map(|index| CustodianSecrets::generate(index).unwrap())
            .collect::<Vec<_>>();
        let public = secrets
            .iter()
            .map(CustodianSecrets::public)
            .collect::<Vec<_>>();
        let registry_hash = custodian_registry_hash(&public).unwrap();
        let custodians = public
            .iter()
            .map(|value| IncrementalCustodianPublicV2 {
                index: value.index,
                encryption_public_key: value.encryption_public_key,
                attestation_public_key: value.attestation_public_key,
            })
            .collect::<Vec<_>>();
        let program_id = [8; 32];
        let proof_marker = sp1_deferred_proof_marker(program_id, &public_values);
        let context = incremental_previous_transaction_bundle_context_v2(
            program_id,
            &public_values,
            proof_marker,
            registry_hash,
        );
        let child_witness = vec![35; 96];
        let bundle = create_bundle(context, &child_witness, &public).unwrap();
        let receipt = IncrementalPreviousTransactionReceiptV2 {
            program_id,
            public_values: public_values.clone(),
            proof_marker,
            bundle_root: bundle.root().unwrap(),
            bundle_context: context,
            child_witness_len: bundle.witness_len,
            custody_receipts: secrets[..RECOVERY_THRESHOLD]
                .iter()
                .map(|secret| secret.custody_receipt(&bundle).unwrap())
                .collect(),
        };
        let mut compact = IncrementalTransitionSettlementV2::compact(source).unwrap();
        compact
            .authenticate_opened_input(2, receipt.clone())
            .unwrap();
        assert!(compact.previous_transactions.is_empty());
        let (_, raw, opened, _, root) = compact.expand().unwrap();
        assert!(raw.is_empty());
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].previous_txid, [31; 32]);
        assert_eq!(
            root,
            incremental_previous_transaction_projection_root_v2(&[public_values]).unwrap()
        );

        let mut input = IncrementalSettlementChildInputV2 {
            version: INCREMENTAL_SETTLEMENT_CHILD_VERSION_V2,
            configuration: configuration(),
            settlement: compact,
            previous_transaction_custodians: custodians,
            deposits: vec![],
            successor_forced_processed_cursor: (u64::MAX as u128) + 11,
            withdrawals: vec![],
            bond_actions: vec![],
        };
        input
            .configuration
            .previous_transaction_custodian_registry_hash = registry_hash;
        assert_ne!(
            execute_incremental_settlement_child_v2_with_consensus_verifier(
                &input,
                &MarkerVerifier,
            )
            .unwrap_err(),
            IncrementalSettlementChildErrorV2::InvalidPreviousTransactionProof
        );
        input.settlement.authenticated_previous_transaction_receipts[0].proof_marker[0] ^= 1;
        assert_eq!(
            execute_incremental_settlement_child_v2_with_consensus_verifier(
                &input,
                &MarkerVerifier,
            )
            .unwrap_err(),
            IncrementalSettlementChildErrorV2::InvalidPreviousTransactionProof
        );
    }

    #[test]
    fn compact_recursive_settlement_has_a_universal_parent_witness_bound() {
        // A canonical Elements input or output consumes at least forty bytes;
        // therefore a 400,000-byte transaction has at most 10,000 of each.
        assert!(
            encode::serialize(&TxIn::default()).len()
                >= MIN_ELEMENTS_TRANSACTION_COMPONENT_BYTES_V2
        );
        assert!(
            encode::serialize(&explicit_output([1; 32], 0, Script::new())).len()
                >= MIN_ELEMENTS_TRANSACTION_COMPONENT_BYTES_V2
        );

        let collateral_input = IncrementalCollateralInputOpeningV2 {
            input_index: u32::MAX,
            previous_transaction_index: Some(u16::MAX),
            authenticated_previous_projection_index: None,
            previous_vout: u32::MAX,
            amount: u64::MAX,
            asset_blinding_factor: [u8::MAX; 32],
            value_blinding_factor: [u8::MAX; 32],
            role: CollateralInputRoleV2::InsuranceReserve,
        };
        let bond_input = IncrementalBondInputOpeningV2 {
            input_index: u32::MAX,
            previous_transaction_index: Some(u16::MAX),
            authenticated_source_projection_index: None,
            authenticated_previous_projection_index: None,
            previous_vout: u32::MAX,
            amount: u64::MAX,
            asset_blinding_factor: [u8::MAX; 32],
            value_blinding_factor: [u8::MAX; 32],
            role: BondInputRoleV2::StagedRedemptionEnqueue {
                redemption_id: [1; 32],
                staging_intent_id: [2; 32],
                claimant: [3; 32],
                staging_script_sha256: [4; 32],
                source_txid: [5; 32],
                source_vout: u32::MAX,
            },
        };
        let collateral_output = CollateralOutputOpeningV2 {
            output_index: u32::MAX,
            amount: u64::MAX,
            asset_blinding_factor: [u8::MAX; 32],
            value_blinding_factor: [u8::MAX; 32],
            role: CollateralOutputRoleV2::BondRedemptionPayment {
                redemption_id: [6; 32],
                recipient_script_sha256: [7; 32],
            },
        };
        let bond_output = BondOutputOpeningV2 {
            output_index: u32::MAX,
            amount: u64::MAX,
            asset_blinding_factor: [u8::MAX; 32],
            value_blinding_factor: [u8::MAX; 32],
            role: BondOutputRoleV2::CancelledRedemptionReturn {
                redemption_id: [8; 32],
                claimant: [9; 32],
                recipient_script_sha256: [10; 32],
                cancellation_id: [11; 32],
            },
        };
        for opening_size in [
            fixed_size(&collateral_input),
            fixed_size(&bond_input),
            fixed_size(&collateral_output),
            fixed_size(&bond_output),
        ] {
            assert!(opening_size <= MAX_INCREMENTAL_SETTLEMENT_OPENING_BYTES_V2);
        }

        let action = BondSettlementActionV2::EnqueueRedemption {
            redemption_id: [12; 32],
            staging_intent_id: [13; 32],
            claimant: [14; 32],
            bond_share_amount: u64::MAX,
            staging_script_sha256: [15; 32],
            source_txid: [16; 32],
            source_vout: u32::MAX,
            source_authorization_commitment: [17; 32],
            refund_script_sha256: [18; 32],
            refund_not_before_parent_height: u64::MAX,
            destination_script_sha256: [19; 32],
        };
        let withdrawal = SuccessorSignedWithdrawalRequestV2 {
            request: SuccessorWithdrawalRequestV2 {
                version: SuccessorWithdrawalRequestV2::VERSION,
                chain_id: [20; 32],
                trader: XOnlyKey([21; 32]),
                nonce: (u64::MAX as u128) + 1,
                amount: u64::MAX,
                destination_script_hash: [22; 32],
                requested_height: u64::MAX,
                not_before_height: u64::MAX,
            },
            signature: Signature64([u8::MAX; 64]),
        };
        assert!(fixed_size(&action) <= MAX_INCREMENTAL_SETTLEMENT_ACTION_BYTES_V2);
        assert!(fixed_size(&withdrawal) <= MAX_INCREMENTAL_SETTLEMENT_ACTION_BYTES_V2);
        assert_eq!(MAX_INCREMENTAL_SETTLEMENT_TRANSACTION_COMPONENTS_V2, 10_000);
        assert_eq!(MAX_INCREMENTAL_SETTLEMENT_TXOUT_WITNESS_BYTES_V2, 13_398);
        assert_eq!(
            MAX_INCREMENTAL_SETTLEMENT_PREVIOUS_RECEIPT_FIXED_BYTES_V2,
            566
        );
        assert_eq!(
            MAX_INCREMENTAL_SETTLEMENT_PREVIOUS_RECEIPTS_BYTES_V2,
            7_820_000
        );
        assert_eq!(
            MAX_INCREMENTAL_SETTLEMENT_STAGING_PROJECTIONS_BYTES_V2,
            899_008
        );
        assert_eq!(
            INCREMENTAL_SETTLEMENT_COMPACT_REACHABLE_CEILING_V2,
            12_268_832
        );
        assert_eq!(
            V18_SUPERSEDED_RAW_SETTLEMENT_PREDECESSOR_BYTES_V2,
            50_731_648
        );
    }

    #[test]
    fn settlement_child_executes_exact_transaction_and_fixed_public_values() {
        let input = IncrementalSettlementChildInputV2 {
            version: INCREMENTAL_SETTLEMENT_CHILD_VERSION_V2,
            configuration: configuration(),
            settlement: IncrementalTransitionSettlementV2::compact(no_economic_settlement())
                .unwrap(),
            previous_transaction_custodians: vec![],
            deposits: vec![],
            successor_forced_processed_cursor: (u64::MAX as u128) + 11,
            withdrawals: vec![],
            bond_actions: vec![],
        };
        let values = execute_incremental_settlement_child_v2(&input).unwrap();
        assert_eq!(values.forced_processed_cursor, (u64::MAX as u128) + 11);
        assert_eq!(values.deposit_processed_cursor, 12);
        assert_eq!(values.action_root, bond_settlement_action_root_v2(&[]));
        let encoded = values.encode();
        assert_eq!(
            encoded.len(),
            INCREMENTAL_SETTLEMENT_CHILD_PUBLIC_VALUES_LEN_V2
        );
        let projection = decode_incremental_settlement_child_projection_v2(&encoded).unwrap();
        assert_eq!(projection.transition_txid, values.transition_txid);
        assert_eq!(projection.action_root, values.action_root);
        assert_eq!(
            projection.combined_settlement_root,
            values.combined_settlement_root
        );
        assert_eq!(projection.insurance_reserve_input_total, 0);
        assert_eq!(projection.insurance_reserve_output_total, 0);

        let mut transaction_mutation = input;
        transaction_mutation.settlement.transaction.push(0);
        assert!(execute_incremental_settlement_child_v2(&transaction_mutation).is_err());
    }

    #[test]
    fn declared_deposit_must_name_exact_vault_input_outpoint_and_amount() {
        let mut rng = thread_rng();
        let secp = Secp256k1::new();
        let asset_id = AssetId::from_byte_array([1; 32]);
        let asset_blinding_factor = AssetBlindingFactor::from_slice(&[2; 32]).unwrap();
        let value_blinding_factor = ValueBlindingFactor::from_slice(&[3; 32]).unwrap();
        let receiver_secret = SecretKey::new(&mut rng);
        let receiver_public = PublicKey::from_secret_key(&secp, &receiver_secret);
        let ephemeral_secret = SecretKey::new(&mut rng);
        let output = TxOut::with_txout_secrets(
            &mut rng,
            &secp,
            Script::from(vec![0x51, 0x20]),
            receiver_public,
            ephemeral_secret,
            TxOutSecrets::new(asset_id, asset_blinding_factor, 25, value_blinding_factor),
            &[TxOutSecrets::new(
                asset_id,
                AssetBlindingFactor::zero(),
                25,
                ValueBlindingFactor::zero(),
            )],
        )
        .unwrap();
        let previous = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![output],
        };
        let mut settlement = no_economic_settlement();
        settlement.collateral_inputs = vec![CollateralInputOpeningV2 {
            input_index: 2,
            previous_transaction: encode::serialize(&previous),
            previous_vout: 0,
            amount: 25,
            asset_blinding_factor: [2; 32],
            value_blinding_factor: [3; 32],
            role: CollateralInputRoleV2::CollateralVault,
        }];
        let deposit = DepositRequest {
            version: DepositRequest::VERSION,
            chain_id: [4; 32],
            deposit_txid: previous.txid().to_byte_array(),
            deposit_vout: 0,
            usdd_asset_id: [1; 32],
            trader: XOnlyKey([
                0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
                0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
                0x16, 0xf8, 0x17, 0x98,
            ]),
            amount: 25,
            observed_height: 1,
        };
        verify_declared_deposit_inputs(&settlement, std::slice::from_ref(&deposit), [1; 32])
            .unwrap();

        let mut wrong_amount = deposit.clone();
        wrong_amount.amount = 24;
        assert_eq!(
            verify_declared_deposit_inputs(&settlement, &[wrong_amount], [1; 32]),
            Err(IncrementalSettlementChildErrorV2::InvalidCompactSettlement)
        );

        for mutation in [
            |request: &mut DepositRequest| request.deposit_txid[0] ^= 1,
            |request: &mut DepositRequest| request.deposit_vout = 1,
            |request: &mut DepositRequest| request.usdd_asset_id[0] ^= 1,
        ] {
            let mut changed = deposit.clone();
            mutation(&mut changed);
            assert_eq!(
                verify_declared_deposit_inputs(&settlement, &[changed], [1; 32]),
                Err(IncrementalSettlementChildErrorV2::InvalidCompactSettlement)
            );
        }
        assert_eq!(
            verify_declared_deposit_inputs(&settlement, &[deposit.clone(), deposit], [1; 32],),
            Err(IncrementalSettlementChildErrorV2::InvalidCompactSettlement)
        );
    }

    #[test]
    fn action_root_binds_order_variant_and_every_field() {
        let first = BondSettlementActionV2::Subscription {
            subscription_id: [11; 32],
            usdd_contribution_amount: 12,
            bond_share_amount: 13,
            recipient_script_sha256: [14; 32],
        };
        let mut changed = first;
        if let BondSettlementActionV2::Subscription {
            ref mut bond_share_amount,
            ..
        } = changed
        {
            *bond_share_amount += 1;
        }
        assert_ne!(
            bond_settlement_action_root_v2(&[first]),
            bond_settlement_action_root_v2(&[changed])
        );
        assert_ne!(
            bond_settlement_action_root_v2(&[first, changed]),
            bond_settlement_action_root_v2(&[changed, first])
        );
    }
}
