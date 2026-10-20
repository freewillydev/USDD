// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISP1VerifierV610} from "../interfaces/ISP1VerifierV610.sol";

contract MockSP1VerifierV610 is ISP1VerifierV610 {
    bytes32 private constant IDENTITY =
        0x4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696;

    bytes32 public immutable EXPECTED_PROGRAM_VKEY;
    bytes32 public immutable EXPECTED_PUBLIC_VALUES_HASH;
    bytes32 public immutable EXPECTED_PROOF_HASH;

    constructor(
        bytes32 expectedProgramVKey,
        bytes32 expectedPublicValuesHash,
        bytes32 expectedProofHash
    ) {
        EXPECTED_PROGRAM_VKEY = expectedProgramVKey;
        EXPECTED_PUBLIC_VALUES_HASH = expectedPublicValuesHash;
        EXPECTED_PROOF_HASH = expectedProofHash;
    }

    function VERIFIER_HASH() external pure override returns (bytes32) {
        return IDENTITY;
    }

    function verifyProof(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external view override {
        require(programVKey == EXPECTED_PROGRAM_VKEY, "program-vkey");
        require(sha256(publicValues) == EXPECTED_PUBLIC_VALUES_HASH, "public-values");
        require(keccak256(proofBytes) == EXPECTED_PROOF_HASH, "proof");
    }
}
