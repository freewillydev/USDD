// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IControllerAcceptanceRelayV2
/// @notice Immutable proof boundary between the Ethereum vault and the canonical
///         Elements USDD controller.
/// @dev A production implementation must not advance its snapshot unless it
///      proves the configured controller program executed in a valid Elements
///      transaction, the transaction is included in the asserted Elements
///      state, that state is BMM-anchored to the configured parent chain, and
///      the finality policy pinned by `verifierConfigHash` is satisfied.
interface IControllerAcceptanceRelayV2 {
    /// @dev This snapshot is advanced only after the relay verifies a canonical
    ///      controller transition and its configured BMM/finality policy.
    struct ControllerSnapshot {
        bytes32 controllerStateHash;
        bytes32 cumulativeResolutionRoot;
        bytes32 parentBlockHash;
        uint64 controllerSequence;
        uint64 resolutionCount;
        /// @dev Exact next committed deposit nonce eligible for MINT or CANCEL.
        ///      This is not assumed equal to `resolutionCount`; only proved
        ///      source/successor deltas are constrained to move together.
        uint64 nextResolutionNonce;
        uint64 parentBlockHeight;
        uint64 parentMedianTimePast;
        uint256 parentChainwork;
        uint64 ethereumFinalizedSlot;
        uint64 ethereumFinalizedTimestamp;
        /// @dev Weak-subjectivity deadline after the frozen recovery margin.
        uint64 weakSubjectivityValidUntil;
        bytes32 acceptedAnchorStateCommitment;
        bytes32 acceptedAnchorExecutionCheckpointHash;
        uint64 acceptedAnchorSequence;
        uint64 acceptedAt;
        uint64 admissionValidUntil;
    }

    /// @notice Domain-separated identity of the relay's security model.
    /// @dev Consumers must pin this value. ABI compatibility alone must never
    ///      permit the weaker miner-certificate profile to substitute for the
    ///      strong recursive-Elements execution profile.
    function securityModelId() external view returns (bytes32);

    /// @notice Identity of the proof program used by this relay.
    function verifierProgramId() external view returns (bytes32);

    /// @notice Commitment to chain, controller, BMM, and finality configuration.
    function verifierConfigHash() external view returns (bytes32);

    /// @notice Exact `TerminalVaultPolicyV2::policy_hash` authorized by this
    ///         relay's immutable controller configuration.
    function inboundVaultPolicyHash() external view returns (bytes32);

    /// @notice Latest canonical controller snapshot accepted by the relay.
    /// @dev The vault treats `admissionValidUntil` only as an upper bound. It
    ///      independently enforces lease duration and minimum remaining time.
    function controllerSnapshot() external view returns (ControllerSnapshot memory);
}
