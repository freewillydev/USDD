// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IBip300RedemptionVerifier} from "../interfaces/IBip300RedemptionVerifier.sol";

/// @notice TEST ONLY. Treats the 32-byte proof as the expected statement.
/// @dev This contract proves no Bitcoin work or M6 approval and must never be
///      used in production.
contract MockBip300RedemptionVerifier is IBip300RedemptionVerifier {
    bytes32 public immutable override verifierProgramId;
    bytes32 public immutable override verifierConfigHash;

    constructor(bytes32 programId, bytes32 configHash) {
        verifierProgramId = programId;
        verifierConfigHash = configHash;
    }

    function verify(bytes32 statement, bytes calldata approvalProof) external pure returns (bool) {
        if (approvalProof.length != 32) return false;
        bytes32 supplied;
        assembly ("memory-safe") {
            supplied := calldataload(approvalProof.offset)
        }
        return supplied == statement;
    }
}
