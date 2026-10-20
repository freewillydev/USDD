//! Exact upper-bound accounting for the fresh incremental successor witness.
//!
//! This module deliberately proves that the current monolithic composition is
//! *not* a valid 16 MiB recovery design.  It prevents individual green bounds
//! from being accidentally added as though they were alternatives rather than
//! simultaneously required proof classes.

use ecx_protocol_core::{
    MAX_CHAINED_ORDER_INDEX_TRANSCRIPT_BYTES_V2, MAX_DEFICIT_INDEX_RANGE_PROOF_BYTES_V2,
    MAX_RISK_EXTREMA_BATCH_BYTES_V2, MAX_SHARED_DEFICIT_INDEX_UPDATE_BATCH_BYTES_V2,
    MAX_SPARSE_MERKLE_SUM_UPDATE_BATCH_BYTES_V2, MAX_SPARSE_NULLIFIER_UPDATE_BATCH_BYTES_V2,
};
use ecx_witness_availability::{
    CUSTODY_RECEIPT_CANONICAL_LEN, MAX_WITNESS_BYTES, RECOVERY_THRESHOLD,
};

use crate::{
    INCREMENTAL_ACCOUNT_ACTION_CHILD_PUBLIC_VALUES_LEN_V2,
    INCREMENTAL_ACCOUNT_ACTION_REACHABLE_ENCODING_CEILING_V2,
    INCREMENTAL_BOND_ACTION_CHILD_PUBLIC_VALUES_LEN_V2,
    INCREMENTAL_BOND_ACTION_REACHABLE_ENCODING_CEILING_V2,
    INCREMENTAL_DEFICIT_CHILD_PUBLIC_VALUES_LEN_V2,
    INCREMENTAL_DEFICIT_CHILD_REACHABLE_ENCODING_CEILING_V2,
    INCREMENTAL_ECONOMIC_ACTION_CHILD_PUBLIC_VALUES_LEN_V2,
    INCREMENTAL_ECONOMIC_ACTION_REACHABLE_ENCODING_CEILING_V2,
    INCREMENTAL_FORCED_ACTION_CHILD_PUBLIC_VALUES_LEN_V2,
    INCREMENTAL_FORCED_ACTION_REACHABLE_ENCODING_CEILING_V2,
    INCREMENTAL_FUNDING_ORACLE_CHILD_PUBLIC_VALUES_LEN_V2,
    INCREMENTAL_FUNDING_ORACLE_CHILD_REACHABLE_ENCODING_CEILING_V2,
    INCREMENTAL_INBOX_SOURCE_CHILD_PUBLIC_VALUES_LEN_V2,
    INCREMENTAL_INBOX_SOURCE_COMPACT_REACHABLE_CEILING_V2,
    INCREMENTAL_NULLIFIER_CHILD_PUBLIC_VALUES_LEN_V2,
    INCREMENTAL_NULLIFIER_CHILD_REACHABLE_ENCODING_CEILING_V2,
    INCREMENTAL_ORDER_CHILD_PUBLIC_VALUES_LEN_V2,
    INCREMENTAL_ORDER_CHILD_REACHABLE_ENCODING_CEILING_V2,
    INCREMENTAL_RISK_CHILD_PUBLIC_VALUES_LEN_V2,
    INCREMENTAL_RISK_CHILD_REACHABLE_ENCODING_CEILING_V2,
    INCREMENTAL_SETTLEMENT_CHILD_PUBLIC_VALUES_LEN_V2,
    INCREMENTAL_SETTLEMENT_COMPACT_REACHABLE_CEILING_V2,
    INCREMENTAL_TRADER_CHILD_PUBLIC_VALUES_LEN_V2,
    INCREMENTAL_TRADER_CHILD_REACHABLE_ENCODING_CEILING_V2,
    MAX_INCREMENTAL_ACCOUNT_ACTION_CHILD_INPUT_BYTES_V2,
    MAX_INCREMENTAL_BOND_ACTION_CHILD_INPUT_BYTES_V2, MAX_INCREMENTAL_DEFICIT_CHILD_INPUT_BYTES_V2,
    MAX_INCREMENTAL_ECONOMIC_ACTION_CHILD_INPUT_BYTES_V2,
    MAX_INCREMENTAL_FORCED_ACTION_CHILD_INPUT_BYTES_V2,
    MAX_INCREMENTAL_FUNDING_ORACLE_CHILD_INPUT_BYTES_V2,
    MAX_INCREMENTAL_INBOX_SOURCE_CHILD_INPUT_BYTES_V2,
    MAX_INCREMENTAL_NULLIFIER_CHILD_INPUT_BYTES_V2, MAX_INCREMENTAL_ORDER_CHILD_INPUT_BYTES_V2,
    MAX_INCREMENTAL_RISK_CHILD_INPUT_BYTES_V2, MAX_INCREMENTAL_SETTLEMENT_CHILD_INPUT_BYTES_V2,
    MAX_INCREMENTAL_TRADER_CHILD_INPUT_BYTES_V2,
};

pub const INCREMENTAL_ENDPOINT_RANGE_PROOF_COUNT_V2: usize = 4;
pub const INCREMENTAL_DEFICIT_UPDATE_TREE_COUNT_V2: usize = 2;
pub const INCREMENTAL_NULLIFIER_TREE_COUNT_V2: usize = 2;

pub const INCREMENTAL_TRADER_CHILD_CEILING_V2: usize = MAX_SPARSE_MERKLE_SUM_UPDATE_BATCH_BYTES_V2;
pub const INCREMENTAL_DEFICIT_CHILD_CEILING_V2: usize = INCREMENTAL_DEFICIT_UPDATE_TREE_COUNT_V2
    * MAX_SHARED_DEFICIT_INDEX_UPDATE_BATCH_BYTES_V2
    + INCREMENTAL_ENDPOINT_RANGE_PROOF_COUNT_V2 * MAX_DEFICIT_INDEX_RANGE_PROOF_BYTES_V2;
pub const INCREMENTAL_RISK_CHILD_CEILING_V2: usize = MAX_RISK_EXTREMA_BATCH_BYTES_V2;
pub const INCREMENTAL_ORDER_CHILD_CEILING_V2: usize = MAX_CHAINED_ORDER_INDEX_TRANSCRIPT_BYTES_V2;
pub const INCREMENTAL_NULLIFIER_CHILD_CEILING_V2: usize =
    INCREMENTAL_NULLIFIER_TREE_COUNT_V2 * MAX_SPARSE_NULLIFIER_UPDATE_BATCH_BYTES_V2;

/// Conservative sum of every proof class already required together by
/// `IncrementalSuccessorWitnessV2`. This excludes framing, settlement, inbox,
/// oracle/funding source proofs, matcher receipts and availability metadata,
/// so exceeding 16 MiB here is conclusive.
pub const INCREMENTAL_MONOLITHIC_STATE_WITNESS_CEILING_V2: usize =
    MAX_SPARSE_MERKLE_SUM_UPDATE_BATCH_BYTES_V2
        + INCREMENTAL_DEFICIT_UPDATE_TREE_COUNT_V2 * MAX_SHARED_DEFICIT_INDEX_UPDATE_BATCH_BYTES_V2
        + MAX_CHAINED_ORDER_INDEX_TRANSCRIPT_BYTES_V2
        + MAX_RISK_EXTREMA_BATCH_BYTES_V2
        + INCREMENTAL_NULLIFIER_TREE_COUNT_V2 * MAX_SPARSE_NULLIFIER_UPDATE_BATCH_BYTES_V2
        + INCREMENTAL_ENDPOINT_RANGE_PROOF_COUNT_V2 * MAX_DEFICIT_INDEX_RANGE_PROOF_BYTES_V2;

/// The partitioned recursive recovery theorem: every child has an enforced
/// accepted-input ceiling below 16 MiB, while the outer recovery record carries
/// only the twelve exact custody descriptors. This does not assert that the
/// successor's still-incomplete migration and node-admission obligations are
/// production complete.
pub const INCREMENTAL_SUCCESSOR_RECOVERY_BOUND_PROVEN_V2: bool = true;

/// Exact hard decoder ceilings for the twelve independently encrypted child
/// witnesses. Together with `INCREMENTAL_CHILD_REACHABLE_ENCODING_CEILINGS_V2`
/// these establish that every currently reachable encoded child input fits its
/// enforced decoder cap and the availability codec's per-bundle limit. The
/// release remains false for the separate semantic, migration, identity and
/// migration and node-admission gates documented above.
pub const INCREMENTAL_CHILD_INPUT_CEILINGS_V2: [usize; 12] = [
    MAX_INCREMENTAL_TRADER_CHILD_INPUT_BYTES_V2,
    MAX_INCREMENTAL_DEFICIT_CHILD_INPUT_BYTES_V2,
    MAX_INCREMENTAL_RISK_CHILD_INPUT_BYTES_V2,
    MAX_INCREMENTAL_ORDER_CHILD_INPUT_BYTES_V2,
    MAX_INCREMENTAL_NULLIFIER_CHILD_INPUT_BYTES_V2,
    MAX_INCREMENTAL_FUNDING_ORACLE_CHILD_INPUT_BYTES_V2,
    MAX_INCREMENTAL_SETTLEMENT_CHILD_INPUT_BYTES_V2,
    MAX_INCREMENTAL_INBOX_SOURCE_CHILD_INPUT_BYTES_V2,
    MAX_INCREMENTAL_BOND_ACTION_CHILD_INPUT_BYTES_V2,
    MAX_INCREMENTAL_ECONOMIC_ACTION_CHILD_INPUT_BYTES_V2,
    MAX_INCREMENTAL_ACCOUNT_ACTION_CHILD_INPUT_BYTES_V2,
    MAX_INCREMENTAL_FORCED_ACTION_CHILD_INPUT_BYTES_V2,
];

/// Wrapper-level reachable encoding proofs in the exact child-class order.
/// `None` is deliberately distinct from a hard decoder ceiling: it means a
/// valid maximum-shape input theorem is still absent for that child.
pub const INCREMENTAL_CHILD_REACHABLE_ENCODING_CEILINGS_V2: [Option<usize>; 12] = [
    Some(INCREMENTAL_TRADER_CHILD_REACHABLE_ENCODING_CEILING_V2),
    Some(INCREMENTAL_DEFICIT_CHILD_REACHABLE_ENCODING_CEILING_V2),
    Some(INCREMENTAL_RISK_CHILD_REACHABLE_ENCODING_CEILING_V2),
    Some(INCREMENTAL_ORDER_CHILD_REACHABLE_ENCODING_CEILING_V2),
    Some(INCREMENTAL_NULLIFIER_CHILD_REACHABLE_ENCODING_CEILING_V2),
    Some(INCREMENTAL_FUNDING_ORACLE_CHILD_REACHABLE_ENCODING_CEILING_V2),
    Some(INCREMENTAL_SETTLEMENT_COMPACT_REACHABLE_CEILING_V2),
    Some(INCREMENTAL_INBOX_SOURCE_COMPACT_REACHABLE_CEILING_V2),
    Some(INCREMENTAL_BOND_ACTION_REACHABLE_ENCODING_CEILING_V2),
    Some(INCREMENTAL_ECONOMIC_ACTION_REACHABLE_ENCODING_CEILING_V2),
    Some(INCREMENTAL_ACCOUNT_ACTION_REACHABLE_ENCODING_CEILING_V2),
    Some(INCREMENTAL_FORCED_ACTION_REACHABLE_ENCODING_CEILING_V2),
];

pub const INCREMENTAL_CHILD_PUBLIC_VALUES_LENGTHS_V2: [usize; 12] = [
    INCREMENTAL_TRADER_CHILD_PUBLIC_VALUES_LEN_V2,
    INCREMENTAL_DEFICIT_CHILD_PUBLIC_VALUES_LEN_V2,
    INCREMENTAL_RISK_CHILD_PUBLIC_VALUES_LEN_V2,
    INCREMENTAL_ORDER_CHILD_PUBLIC_VALUES_LEN_V2,
    INCREMENTAL_NULLIFIER_CHILD_PUBLIC_VALUES_LEN_V2,
    INCREMENTAL_FUNDING_ORACLE_CHILD_PUBLIC_VALUES_LEN_V2,
    INCREMENTAL_SETTLEMENT_CHILD_PUBLIC_VALUES_LEN_V2,
    INCREMENTAL_INBOX_SOURCE_CHILD_PUBLIC_VALUES_LEN_V2,
    INCREMENTAL_BOND_ACTION_CHILD_PUBLIC_VALUES_LEN_V2,
    INCREMENTAL_ECONOMIC_ACTION_CHILD_PUBLIC_VALUES_LEN_V2,
    INCREMENTAL_ACCOUNT_ACTION_CHILD_PUBLIC_VALUES_LEN_V2,
    INCREMENTAL_FORCED_ACTION_CHILD_PUBLIC_VALUES_LEN_V2,
];

pub const INCREMENTAL_CHILD_PUBLIC_VALUES_TOTAL_BYTES_V2: usize =
    INCREMENTAL_TRADER_CHILD_PUBLIC_VALUES_LEN_V2
        + INCREMENTAL_DEFICIT_CHILD_PUBLIC_VALUES_LEN_V2
        + INCREMENTAL_RISK_CHILD_PUBLIC_VALUES_LEN_V2
        + INCREMENTAL_ORDER_CHILD_PUBLIC_VALUES_LEN_V2
        + INCREMENTAL_NULLIFIER_CHILD_PUBLIC_VALUES_LEN_V2
        + INCREMENTAL_FUNDING_ORACLE_CHILD_PUBLIC_VALUES_LEN_V2
        + INCREMENTAL_SETTLEMENT_CHILD_PUBLIC_VALUES_LEN_V2
        + INCREMENTAL_INBOX_SOURCE_CHILD_PUBLIC_VALUES_LEN_V2
        + INCREMENTAL_BOND_ACTION_CHILD_PUBLIC_VALUES_LEN_V2
        + INCREMENTAL_ECONOMIC_ACTION_CHILD_PUBLIC_VALUES_LEN_V2
        + INCREMENTAL_ACCOUNT_ACTION_CHILD_PUBLIC_VALUES_LEN_V2
        + INCREMENTAL_FORCED_ACTION_CHILD_PUBLIC_VALUES_LEN_V2;

/// Fixed descriptor fields: version, class, program ID, PV length, proof
/// marker, bundle root, context, witness length, and receipt count.
pub const INCREMENTAL_CHILD_DESCRIPTOR_FIXED_BYTES_V2: usize = 143;
pub const INCREMENTAL_TWELVE_CHILD_COMPACT_DESCRIPTOR_BYTES_V2: usize = (12
    * (INCREMENTAL_CHILD_DESCRIPTOR_FIXED_BYTES_V2
        + RECOVERY_THRESHOLD * CUSTODY_RECEIPT_CANONICAL_LEN))
    + INCREMENTAL_CHILD_PUBLIC_VALUES_TOTAL_BYTES_V2;
const _: () = assert!(INCREMENTAL_TWELVE_CHILD_COMPACT_DESCRIPTOR_BYTES_V2 < MAX_WITNESS_BYTES);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalRecoveryBudgetV2 {
    pub state_witness_ceiling: usize,
    pub recovery_envelope_limit: usize,
    pub minimum_excess_before_external_inputs: usize,
}

pub const fn incremental_recovery_budget_v2() -> IncrementalRecoveryBudgetV2 {
    IncrementalRecoveryBudgetV2 {
        state_witness_ceiling: INCREMENTAL_MONOLITHIC_STATE_WITNESS_CEILING_V2,
        recovery_envelope_limit: MAX_WITNESS_BYTES,
        minimum_excess_before_external_inputs: INCREMENTAL_MONOLITHIC_STATE_WITNESS_CEILING_V2
            - MAX_WITNESS_BYTES,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monolithic_incremental_classes_exceed_recovery_before_settlement_and_sources() {
        let budget = incremental_recovery_budget_v2();
        assert_eq!(budget.state_witness_ceiling, 31_719_424);
        assert_eq!(budget.recovery_envelope_limit, 16_777_216);
        assert_eq!(budget.minimum_excess_before_external_inputs, 14_942_208);
        assert!(budget.state_witness_ceiling > budget.recovery_envelope_limit);
    }

    #[test]
    fn every_simultaneous_state_class_is_counted_once() {
        assert_eq!(INCREMENTAL_DEFICIT_UPDATE_TREE_COUNT_V2, 2);
        assert_eq!(INCREMENTAL_NULLIFIER_TREE_COUNT_V2, 2);
        assert_eq!(INCREMENTAL_ENDPOINT_RANGE_PROOF_COUNT_V2, 4);
        assert_eq!(MAX_RISK_EXTREMA_BATCH_BYTES_V2, 4 * 1024 * 1024);
        assert_eq!(MAX_CHAINED_ORDER_INDEX_TRANSCRIPT_BYTES_V2, 4 * 1024 * 1024);
    }

    #[test]
    fn recursive_state_class_partition_fits_each_recoverable_child() {
        assert_eq!(INCREMENTAL_TRADER_CHILD_CEILING_V2, 6 * 1024 * 1024);
        assert_eq!(
            INCREMENTAL_DEFICIT_CHILD_CEILING_V2,
            14 * 1024 * 1024 + 4 * 64 * 1024
        );
        assert_eq!(INCREMENTAL_RISK_CHILD_CEILING_V2, 4 * 1024 * 1024);
        assert_eq!(INCREMENTAL_ORDER_CHILD_CEILING_V2, 4 * 1024 * 1024);
        assert_eq!(INCREMENTAL_NULLIFIER_CHILD_CEILING_V2, 2 * 1024 * 1024);
        for ceiling in [
            INCREMENTAL_TRADER_CHILD_CEILING_V2,
            INCREMENTAL_DEFICIT_CHILD_CEILING_V2,
            INCREMENTAL_RISK_CHILD_CEILING_V2,
            INCREMENTAL_ORDER_CHILD_CEILING_V2,
            INCREMENTAL_NULLIFIER_CHILD_CEILING_V2,
        ] {
            assert!(ceiling < MAX_WITNESS_BYTES);
        }
        let superseded_combined_child = [
            INCREMENTAL_TRADER_CHILD_CEILING_V2,
            INCREMENTAL_DEFICIT_CHILD_CEILING_V2,
            INCREMENTAL_RISK_CHILD_CEILING_V2,
        ]
        .into_iter()
        .sum::<usize>();
        assert!(superseded_combined_child > MAX_WITNESS_BYTES);
    }

    #[test]
    fn twelve_child_decoder_and_compact_descriptor_limits_are_exact() {
        assert_eq!(INCREMENTAL_CHILD_INPUT_CEILINGS_V2.len(), 12);
        assert_eq!(INCREMENTAL_CHILD_PUBLIC_VALUES_LENGTHS_V2.len(), 12);
        assert_eq!(
            INCREMENTAL_CHILD_PUBLIC_VALUES_LENGTHS_V2
                .into_iter()
                .sum::<usize>(),
            INCREMENTAL_CHILD_PUBLIC_VALUES_TOTAL_BYTES_V2
        );
        assert_eq!(INCREMENTAL_CHILD_PUBLIC_VALUES_TOTAL_BYTES_V2, 5_086);
        assert!(INCREMENTAL_CHILD_INPUT_CEILINGS_V2
            .into_iter()
            .all(|ceiling| ceiling <= MAX_WITNESS_BYTES));
        assert_eq!(INCREMENTAL_TWELVE_CHILD_COMPACT_DESCRIPTOR_BYTES_V2, 11_770);
        assert_eq!(
            crate::INCREMENTAL_FORCED_ACTION_REACHABLE_ENCODING_CEILING_V2,
            164_921
        );
        assert_eq!(
            crate::INCREMENTAL_ACCOUNT_ACTION_REACHABLE_ENCODING_CEILING_V2,
            961_332
        );
        assert_eq!(
            crate::INCREMENTAL_NULLIFIER_CHILD_REACHABLE_ENCODING_CEILING_V2,
            1_579_457
        );
    }

    #[test]
    fn reachable_child_matrix_proves_all_twelve_wrapper_ceilings() {
        assert_eq!(INCREMENTAL_CHILD_REACHABLE_ENCODING_CEILINGS_V2.len(), 12);
        assert_eq!(
            INCREMENTAL_CHILD_REACHABLE_ENCODING_CEILINGS_V2
                .iter()
                .filter(|ceiling| ceiling.is_some())
                .count(),
            12
        );
        for (reachable, decoder) in INCREMENTAL_CHILD_REACHABLE_ENCODING_CEILINGS_V2
            .into_iter()
            .zip(INCREMENTAL_CHILD_INPUT_CEILINGS_V2)
        {
            if let Some(reachable) = reachable {
                assert!(reachable < decoder);
            }
        }
        assert!(INCREMENTAL_CHILD_REACHABLE_ENCODING_CEILINGS_V2
            .into_iter()
            .flatten()
            .all(|ceiling| ceiling < MAX_WITNESS_BYTES));
    }

    #[test]
    fn nested_source_projection_eliminates_raw_parent_child_copy() {
        assert_eq!(
            crate::SUCCESSOR_REACHABLE_INBOX_SOURCE_TRANSACTION_BYTES_V2,
            50_331_648
        );
        assert_eq!(
            crate::V18_SUPERSEDED_RAW_SETTLEMENT_PREDECESSOR_BYTES_V2,
            50_731_648
        );
        assert_eq!(
            crate::INCREMENTAL_SOURCE_TRANSACTION_CHILD_REACHABLE_CEILING_V2,
            917_504
        );
        assert_eq!(
            crate::MAX_INCREMENTAL_SOURCE_TRANSACTION_CHILD_INPUT_BYTES_V2,
            1_048_576
        );
        assert_eq!(
            crate::INCREMENTAL_SOURCE_TRANSACTION_CHILD_PUBLIC_VALUES_LEN_V2,
            369
        );
    }

    #[test]
    fn economic_action_child_reachable_encoding_is_below_its_decoder_cap() {
        assert_eq!(
            crate::INCREMENTAL_ECONOMIC_ACTION_REACHABLE_ENCODING_CEILING_V2,
            317_440
        );
    }

    #[test]
    fn risk_child_reachable_encoding_is_below_its_decoder_cap() {
        assert_eq!(
            crate::INCREMENTAL_RISK_CHILD_REACHABLE_ENCODING_CEILING_V2,
            4_396_032
        );
    }
}
