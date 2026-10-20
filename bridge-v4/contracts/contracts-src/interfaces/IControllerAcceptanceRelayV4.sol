// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Versioned no-expiry controller boundary. Not ABI-compatible with V2.
/// @dev Implementations must authenticate terminal, parent replay and mined
/// execution receipts, and independently authenticate canonical parent/anchor
/// selection. This interface alone does not establish any of those properties.
interface IControllerAcceptanceRelayV4 {
    /// @dev Exact public projection of BootstrapAcceptanceStateV4. Hashes and
    /// parent chainwork retain the Rust canonical byte order; no hash reversal.
    struct AcceptanceState {
        bytes32 checkpointHash;
        bytes32 controllerStateHash;
        bytes32 cumulativeResolutionRoot;
        uint64 controllerSequence;
        uint64 resolutionCount;
        uint64 nextResolutionNonce;
        bytes32 parentBlockHash;
        uint64 parentBlockHeight;
        uint64 parentMedianTimePast;
        bytes32 parentChainwork;
        uint64 ethereumFinalizedSlot;
        uint64 ethereumFinalizedTimestamp;
    }

    struct ControllerSnapshot {
        AcceptanceState state;
        bytes32 acceptedAnchorStateCommitment;
        bytes32 acceptedAnchorExecutionCheckpointHash;
        uint64 acceptedAnchorSequence;
        uint64 acceptedAt;
        /// @dev Freshness bound for NEW admissions only, not configuration
        /// expiry or a deadline for claiming an already accepted resolution.
        uint64 admissionValidUntil;
    }

    // Consumers must pin the distinct security model, actual code identity and
    // verifier bindings; matching an ABI never authorizes a weaker proof role.
    function securityModelId() external view returns (bytes32);
    function verifierProgramId() external view returns (bytes32);
    function verifierConfigHash() external view returns (bytes32);
    function inboundVaultPolicyHash() external view returns (bytes32);
    function controllerSnapshot() external view returns (ControllerSnapshot memory);
}
