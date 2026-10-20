// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IV11AllSlotReplayProofVerifier
/// @notice Opaque proof boundary for the incompatible V11 all-slot parent
///         replay profile.
/// @dev This interface is intentionally distinct from the strong Elements
///      execution verifier. A successful call authenticates only the exact
///      V11 parent-replay journal whose canonical bytes hash to
///      `publicValuesHash`.
interface IV11AllSlotReplayProofVerifier {
    function verifierProgramId() external view returns (bytes32);

    function verifierConfigHash() external view returns (bytes32);

    function allSlotReplayProfileCommitment() external view returns (bytes32);

    /// @notice Exact live finality configuration committed by the replay
    ///         profile whose journal this verifier accepts.
    /// @dev This cross-binds the opaque proof boundary to the relay's live
    ///      retained-range finality source. A verifier for profile A must
    ///      never be combined with finality configuration B.
    function canonicalFinalityConfigurationHash()
        external
        view
        returns (bytes32);

    function exactParentGenesisSerializationHash()
        external
        view
        returns (bytes32);

    function initialAllSlotCheckpointCommitment()
        external
        view
        returns (bytes32);

    function verifyProof(bytes32 publicValuesHash, bytes calldata proof)
        external
        view
        returns (bool);
}
