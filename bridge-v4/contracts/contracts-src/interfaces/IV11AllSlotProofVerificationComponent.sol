// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IV11AllSlotProofVerificationComponent
/// @notice Stateless leaf verifier for the two canonical V11 all-slot journal
///         shapes.
/// @dev The outer adapter pins the component address, runtime code hash,
///      program identity and component configuration. A production component
///      must have no owner, proxy, delegatecall, setter or mutable verification
///      target.
interface IV11AllSlotProofVerificationComponent {
    /// @notice Exact little-endian `hash_u32()` segment identity accepted by recursion.
    /// @dev This identity is semantic configuration even though the outer
    ///      Groth16 proof verifies only the final fold program.
    function componentSegmentProgramId() external view returns (bytes32);

    function componentProgramId() external view returns (bytes32);

    /// @notice Exact BN254 segment program vkey (`bytes32_raw()`).
    function componentSegmentProgramVKey() external view returns (bytes32);

    /// @notice Exact BN254 fold program vkey (`bytes32_raw()`).
    function componentProgramVKey() external view returns (bytes32);

    function componentConfigHash() external view returns (bytes32);

    function verify(bytes32 publicValuesHash, bytes calldata proof)
        external
        view
        returns (bool);
}
