// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IProofVerificationComponent} from "./interfaces/IProofVerificationComponent.sol";
import {ISP1VerifierV610} from "./interfaces/ISP1VerifierV610.sol";

/// @title SP1Groth16ProofComponentV1
/// @notice Stateless bridge between the USDD relay's SHA-256 statement API and
///         Succinct's immutable SP1 v6.1.0 Groth16 verifier.
/// @dev `proof` is exactly `publicValues || groth16ProofBytes`. The immutable
///      public-values length makes the encoding unambiguous. The SP1 verifier
///      address, runtime code hash, verifier identity, program vkey, and public
///      values length are all permanently pinned.
contract SP1Groth16ProofComponentV1 is IProofVerificationComponent {
    bytes32 public constant SP1_V610_GROTH16_VERIFIER_HASH =
        0x4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696;
    uint256 public constant GROTH16_PROOF_BYTES = 356;
    uint256 public constant MAX_PUBLIC_VALUES_BYTES = 4096;

    address public immutable SP1_VERIFIER;
    bytes32 public immutable SP1_VERIFIER_CODEHASH;
    bytes32 public immutable PROGRAM_VKEY;
    uint32 public immutable PUBLIC_VALUES_LENGTH;

    error ZeroIdentity();
    error AddressHasNoCode(address target);
    error VerifierCodeChanged(bytes32 expected, bytes32 actual);
    error WrongVerifierIdentity(bytes32 expected, bytes32 actual);
    error InvalidPublicValuesLength(uint32 actual);

    constructor(
        address sp1Verifier,
        bytes32 sp1VerifierCodehash,
        bytes32 programVKey,
        uint32 publicValuesLength
    ) {
        if (
            sp1Verifier == address(0) || sp1VerifierCodehash == bytes32(0)
                || programVKey == bytes32(0)
        ) revert ZeroIdentity();
        if (publicValuesLength == 0 || publicValuesLength > MAX_PUBLIC_VALUES_BYTES) {
            revert InvalidPublicValuesLength(publicValuesLength);
        }
        if (sp1Verifier.code.length == 0) revert AddressHasNoCode(sp1Verifier);
        if (sp1Verifier.codehash != sp1VerifierCodehash) {
            revert VerifierCodeChanged(sp1VerifierCodehash, sp1Verifier.codehash);
        }
        (bool success, bytes memory result) = sp1Verifier.staticcall(
            abi.encodeCall(ISP1VerifierV610.VERIFIER_HASH, ())
        );
        bytes32 actualIdentity =
            success && result.length == 32 ? abi.decode(result, (bytes32)) : bytes32(0);
        if (actualIdentity != SP1_V610_GROTH16_VERIFIER_HASH) {
            revert WrongVerifierIdentity(SP1_V610_GROTH16_VERIFIER_HASH, actualIdentity);
        }

        SP1_VERIFIER = sp1Verifier;
        SP1_VERIFIER_CODEHASH = sp1VerifierCodehash;
        PROGRAM_VKEY = programVKey;
        PUBLIC_VALUES_LENGTH = publicValuesLength;
    }

    function verify(bytes32 publicValuesHash, bytes calldata proof)
        external
        view
        override
        returns (bool)
    {
        uint256 publicValuesLength = PUBLIC_VALUES_LENGTH;
        if (proof.length != publicValuesLength + GROTH16_PROOF_BYTES) return false;
        if (SP1_VERIFIER.codehash != SP1_VERIFIER_CODEHASH) {
            revert VerifierCodeChanged(SP1_VERIFIER_CODEHASH, SP1_VERIFIER.codehash);
        }

        bytes calldata publicValues = proof[:publicValuesLength];
        bytes calldata groth16Proof = proof[publicValuesLength:];
        if (sha256(publicValues) != publicValuesHash) return false;
        if (bytes4(groth16Proof[:4]) != bytes4(SP1_V610_GROTH16_VERIFIER_HASH)) return false;

        (bool success, bytes memory result) = SP1_VERIFIER.staticcall(
            abi.encodeCall(
                ISP1VerifierV610.verifyProof, (PROGRAM_VKEY, publicValues, groth16Proof)
            )
        );
        return success && result.length == 0;
    }
}
