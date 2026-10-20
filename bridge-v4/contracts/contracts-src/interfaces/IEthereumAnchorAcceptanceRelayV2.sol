// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Canonical proof-accepted V11 Ethereum-anchor history.
interface IEthereumAnchorAcceptanceRelayV2 {
    struct AnchorSnapshot {
        bytes32 stateCommitment;
        bytes32 executionCheckpointHash;
        bytes32 parentBlockHash;
        uint64 sequence;
        uint64 parentBlockHeight;
        uint64 parentMedianTimePast;
        uint256 parentChainwork;
        uint64 ethereumFinalizedSlot;
        uint64 ethereumFinalizedTimestamp;
        uint64 weakSubjectivityValidUntil;
        uint64 acceptedAt;
    }

    function securityModelId() external view returns (bytes32);
    function verifierProgramId() external view returns (bytes32);
    function verifierConfigHash() external view returns (bytes32);
    function anchorSnapshot() external view returns (AnchorSnapshot memory);
    function isAcceptedAnchor(
        bytes32 stateCommitment,
        bytes32 executionCheckpointHash,
        uint64 sequence
    ) external view returns (bool);
}

