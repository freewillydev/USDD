// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Exact external surface used from Succinct's SP1 v6.1.0 verifier.
interface ISP1VerifierV610 {
    function VERIFIER_HASH() external pure returns (bytes32);

    function verifyProof(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external view;
}
