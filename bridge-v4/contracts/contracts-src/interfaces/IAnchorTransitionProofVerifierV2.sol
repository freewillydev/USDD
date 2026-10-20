// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Immutable verifier boundary for one mined V11 Ethereum-anchor transition.
interface IAnchorTransitionProofVerifierV2 {
    function verifierProgramId() external view returns (bytes32);
    function verifierConfigHash() external view returns (bytes32);
    function verifyProof(bytes32 publicValuesHash, bytes calldata proof)
        external
        view
        returns (bool);
}

