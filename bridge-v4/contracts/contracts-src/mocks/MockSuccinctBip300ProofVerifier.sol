// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISuccinctBip300ProofVerifier} from "../interfaces/ISuccinctBip300ProofVerifier.sol";

/// @notice TEST ONLY. Accepts a 32-byte proof equal to the public-values hash.
/// @dev Proves no eCash work, BIP300 transition, M6, or finality.
contract MockSuccinctBip300ProofVerifier is ISuccinctBip300ProofVerifier {
    bytes32 public immutable override verifierProgramId;
    bytes32 public immutable override verifierConfigHash;

    constructor(bytes32 programId, bytes32 configHash) {
        verifierProgramId = programId;
        verifierConfigHash = configHash;
    }

    function verifyProof(bytes32 publicValuesHash, bytes calldata proof)
        external
        pure
        returns (bool)
    {
        if (proof.length != 32) return false;
        bytes32 supplied;
        assembly ("memory-safe") {
            supplied := calldataload(proof.offset)
        }
        return supplied == publicValuesHash;
    }
}
