// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ICanonicalParentFinalityReceiptV11
/// @notice Live retained-range and unique-greatest-work boundary for the
///         incompatible V11 miner-approved controller profile.
/// @dev The controller relay must call this exact pinned interface in the same
///      transaction that accepts a certificate. Caller-supplied serialized
///      receipts, signatures, and proof-local "best chain" claims are not
///      substitutes for this call.
///
/// A successful call attests that:
/// - `prior.checkpoint` is still retained;
/// - `candidate` descends from `prior.checkpoint`;
/// - `observedFinalizedHead` descends from `candidate`;
/// - the observed head is finalized and uniquely greatest-work; and
/// - no available equal-work competing best tip exists.
///
/// A reorg below an already accepted prior cursor, source unavailability, or
/// equal-work ambiguity must revert/fail closed. The relay never rolls its
/// cursor backward.
interface ICanonicalParentFinalityReceiptV11 {
    struct Checkpoint {
        /// Conventional Bitcoin RPC/display byte order.
        bytes32 blockHashDisplay;
        uint32 blockHeight;
        uint32 medianTimePast;
        uint256 cumulativeChainwork;
    }

    struct Cursor {
        bytes32 receiptId;
        uint64 receiptEpoch;
        Checkpoint checkpoint;
    }

    struct RangeRequest {
        bytes32 subject;
        Cursor prior;
        Checkpoint candidate;
    }

    struct RangeReceipt {
        bytes32 receiptId;
        uint64 receiptEpoch;
        Checkpoint observedFinalizedHead;
    }

    function sourceIdentity() external view returns (bytes32);

    function sourceInterfaceHash() external view returns (bytes32);

    function canonicalFinalityConfigurationHash() external view returns (bytes32);

    /// @notice Exact replay profile whose proof journals may populate this
    ///         source's retained fork graph.
    /// @dev This binding is deliberately separate from
    ///      `canonicalFinalityConfigurationHash`: the replay profile commits
    ///      to that finality configuration, so including the profile inside
    ///      the configuration would create a hash cycle.
    function parentReplayProfileCommitment() external view returns (bytes32);

    function initialParentReplayCheckpointCommitment()
        external
        view
        returns (bytes32);

    function verifyRetainedCanonicalRange(RangeRequest calldata request)
        external
        view
        returns (RangeReceipt memory receipt);
}
