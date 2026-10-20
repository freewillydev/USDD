// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IUSDDRedemptionProofVerifierV2
/// @notice Immutable proof boundary for a complete V11 Elements-burn and M6
///         approval transition.
/// @dev A conforming verifier proves all of the following for the statement:
///      (1) the cumulative claim-root transition was executed by the frozen
///      V11 Elements controller, (2) every newly introduced claim identifies a
///      valid destruction of the configured USDD asset, (3) the exact M6 was
///      approved by authentic M3/M4/M6 processing on the configured parent
///      chain, (4) the Elements execution is BMM-anchored to that parent
///      history, and (5) the configured finality policy is satisfied. Neither a
///      raw M6 certificate nor a BIP301 M7 commitment satisfies this interface.
interface IUSDDRedemptionProofVerifierV2 {
    function securityModelId() external view returns (bytes32);

    function verifierProgramId() external view returns (bytes32);

    function verifierConfigHash() external view returns (bytes32);

    function verify(bytes32 statement, bytes calldata proof) external view returns (bool);
}
