// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IControllerTransitionProofVerifierV2
/// @notice Minimal immutable verification boundary for a strong V11 controller
///         acceptance statement.
/// @dev Returning true MUST mean that the proof authenticates all of the
///      public values committed by `publicValuesHash`, including:
///      (1) valid execution of the frozen Elements controller program,
///      (1a) exact recursive authority and keyless fee-reserve outpoint
///           adjacency from the frozen execution checkpoint,
///      (2) canonical inclusion of the exact complete transaction witness and
///          successor state, including the Elements witness commitment,
///      (3) BMM anchoring to the configured parent history, and
///      (4) the exact BMM parent tuple and the weak-subjectivity deadline
///      derived under the configured policy. The separately pinned
///      IParentFinalityRelayV2 establishes canonical fork choice and finality
///      for that tuple. A verifier for only a raw BMM commitment, an RPC
///      observation, or an unanchored SP1 execution is not an implementation
///      of this interface.
interface IControllerTransitionProofVerifierV2 {
    function verifierProgramId() external view returns (bytes32);

    function verifierConfigHash() external view returns (bytes32);

    function verifyProof(bytes32 publicValuesHash, bytes calldata proof)
        external
        view
        returns (bool);
}
