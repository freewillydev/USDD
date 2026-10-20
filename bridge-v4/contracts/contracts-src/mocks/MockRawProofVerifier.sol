// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IRawProofVerifier} from "../interfaces/IRawProofVerifier.sol";

/// @notice TEST ONLY. Treats the 32-byte proof as the expected statement.
/// @dev This contract proves nothing and must never be used in production.
contract MockRawProofVerifier is IRawProofVerifier {
    bytes32 public immutable override verifierProgramId;
    bytes32 public immutable override verifierConfigHash;

    constructor(bytes32 programId, bytes32 configHash) {
        verifierProgramId = programId;
        verifierConfigHash = configHash;
    }

    function verify(bytes32 statement, bytes calldata proof) external pure returns (bool) {
        if (proof.length != 32) return false;
        bytes32 supplied;
        assembly ("memory-safe") {
            supplied := calldataload(proof.offset)
        }
        return supplied == statement;
    }
}
