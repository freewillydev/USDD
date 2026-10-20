// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Generic acceptance verifier for exact statement || policy hash.
/// @dev Both words must be authenticated by the same recursive guest proof.
/// The expected policy belongs to the consuming relay, not verifier bootstrap.
interface IControllerPolicyProofVerifierV4 {
    function verifierProgramId() external view returns (bytes32);
    function verifierConfigHash() external view returns (bytes32);
    function verifyProof(bytes32 statement, bytes32 policyHash, bytes calldata proof)
        external view returns (bool);
}
