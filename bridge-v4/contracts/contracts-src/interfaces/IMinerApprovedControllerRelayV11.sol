// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IMinerApprovedControllerRelayV11
/// @notice Downstream boundary for the explicitly miner-authorized V11
///         controller-certificate profile.
/// @dev This interface is deliberately not IControllerAcceptanceRelayV2.
///      Miner approval does not prove full Elements execution. A consumer for
///      this profile must pin `securityModelId`, the verifier identities, and
///      the relay code/configuration rather than treating this ABI as the
///      stronger recursive-Elements boundary.
interface IMinerApprovedControllerRelayV11 {
    struct ControllerSnapshot {
        bytes32 controllerStateHash;
        bytes32 cumulativeResolutionRoot;
        bytes32 parentBlockHash;
        uint64 controllerSequence;
        uint64 resolutionCount;
        uint64 nextResolutionNonce;
        uint64 parentBlockHeight;
        uint64 parentMedianTimePast;
        uint256 parentChainwork;
        uint64 ethereumFinalizedSlot;
        uint64 ethereumFinalizedTimestamp;
        uint64 weakSubjectivityValidUntil;
        uint64 acceptedAt;
        uint64 admissionValidUntil;
    }

    function securityModelId() external pure returns (bytes32);

    function verifierProgramId() external view returns (bytes32);

    function verifierConfigHash() external view returns (bytes32);

    function controllerSnapshot()
        external
        view
        returns (ControllerSnapshot memory);
}
