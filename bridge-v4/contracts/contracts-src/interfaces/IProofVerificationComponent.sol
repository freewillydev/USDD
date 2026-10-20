// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Stateless leaf component used by the immutable proof-verifier graph.
interface IProofVerificationComponent {
    function verify(bytes32 publicValuesHash, bytes calldata proof) external view returns (bool);
}

