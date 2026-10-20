// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Immutable verification boundary for succinct eCash/BIP300 state transitions.
/// @dev The frozen proof program must validate the complete parent-chain transition,
///      including proof of work, best-chain selection, reorg handling, all 256
///      Drivechain slots, M3/M4/M5/M6 processing, CTIP succession, finality, and
///      the exact USDD accumulator-root M6 exposed in the public values.
interface ISuccinctBip300ProofVerifier {
    function verifierProgramId() external view returns (bytes32);

    function verifierConfigHash() external view returns (bytes32);

    function verifyProof(bytes32 publicValuesHash, bytes calldata proof) external view returns (bool);
}
