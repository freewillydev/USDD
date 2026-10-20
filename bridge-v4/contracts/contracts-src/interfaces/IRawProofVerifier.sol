// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal identity and verification interface for a self-contained verifier.
/// @dev `verifierProgramId` identifies the proved guest/program. The config hash
///      must commit every verification parameter not already captured by that
///      ID, including proof-system/version, verification keys or transparent
///      parameters, recursion policy, and public-input schema. A production
///      verifier must implement these getters immutably in the same audited
///      runtime that implements `verify`.
interface IRawProofVerifier {
    function verifierProgramId() external view returns (bytes32);

    function verifierConfigHash() external view returns (bytes32);

    function verify(bytes32 statement, bytes calldata proof) external view returns (bool);
}
