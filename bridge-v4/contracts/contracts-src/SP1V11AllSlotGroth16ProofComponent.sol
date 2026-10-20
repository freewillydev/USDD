// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISP1VerifierV610} from "./interfaces/ISP1VerifierV610.sol";
import {IV11AllSlotProofVerificationComponent} from
    "./interfaces/IV11AllSlotProofVerificationComponent.sol";

/// @title SP1V11AllSlotGroth16ProofComponent
/// @notice Exact SP1 v6.1.0 Groth16 component for V11 all-slot journals.
/// @dev `proof` is exactly `journalBytes || groth16Proof`. The journal is
///      either the 271-byte no-certificate form or the 449-byte
///      certificate-present form. No other public-value length is accepted.
contract SP1V11AllSlotGroth16ProofComponent is
    IV11AllSlotProofVerificationComponent
{
    bytes32 public constant SP1_V610_GROTH16_VERIFIER_HASH =
        0x4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696;
    bytes32 public constant COMPONENT_CONFIG_DOMAIN =
        sha256("USDD_V11_ALL_SLOT_GROTH16_COMPONENT_CONFIG");
    uint32 public constant NO_CERTIFICATE_PUBLIC_VALUES_BYTES = 271;
    uint32 public constant CERTIFICATE_PUBLIC_VALUES_BYTES = 449;
    uint32 public constant GROTH16_PROOF_BYTES = 356;

    address public immutable SP1_VERIFIER;
    bytes32 public immutable SP1_VERIFIER_CODEHASH;
    bytes32 public immutable override componentSegmentProgramId;
    bytes32 public immutable override componentProgramId;
    bytes32 public immutable override componentSegmentProgramVKey;
    bytes32 public immutable override componentProgramVKey;
    bytes32 public immutable override componentConfigHash;

    error ZeroIdentity();
    error AddressHasNoCode(address target);
    error VerifierCodeChanged(bytes32 expected, bytes32 actual);
    error WrongVerifierIdentity(bytes32 expected, bytes32 actual);

    constructor(
        address sp1Verifier,
        bytes32 sp1VerifierCodehash,
        bytes32 segmentRecursiveVKeyHash,
        bytes32 foldRecursiveVKeyHash,
        bytes32 segmentProgramVKey,
        bytes32 programVKey
    ) {
        if (
            sp1Verifier == address(0)
                || sp1VerifierCodehash == bytes32(0)
                || segmentRecursiveVKeyHash == bytes32(0)
                || foldRecursiveVKeyHash == bytes32(0)
                || segmentRecursiveVKeyHash == foldRecursiveVKeyHash
                || segmentProgramVKey == bytes32(0)
                || programVKey == bytes32(0)
                || segmentProgramVKey == programVKey
        ) revert ZeroIdentity();
        if (sp1Verifier.code.length == 0) {
            revert AddressHasNoCode(sp1Verifier);
        }
        if (sp1Verifier.codehash != sp1VerifierCodehash) {
            revert VerifierCodeChanged(
                sp1VerifierCodehash, sp1Verifier.codehash
            );
        }
        _requireVerifierIdentity(sp1Verifier);

        SP1_VERIFIER = sp1Verifier;
        SP1_VERIFIER_CODEHASH = sp1VerifierCodehash;
        componentSegmentProgramId = segmentRecursiveVKeyHash;
        componentProgramId = foldRecursiveVKeyHash;
        componentSegmentProgramVKey = segmentProgramVKey;
        componentProgramVKey = programVKey;
        componentConfigHash = sha256(
            abi.encodePacked(
                COMPONENT_CONFIG_DOMAIN,
                sp1Verifier,
                sp1VerifierCodehash,
                SP1_V610_GROTH16_VERIFIER_HASH,
                segmentRecursiveVKeyHash,
                foldRecursiveVKeyHash,
                segmentProgramVKey,
                programVKey,
                NO_CERTIFICATE_PUBLIC_VALUES_BYTES,
                CERTIFICATE_PUBLIC_VALUES_BYTES,
                GROTH16_PROOF_BYTES,
                uint8(1)
            )
        );
    }

    function verify(bytes32 publicValuesHash, bytes calldata proof)
        external
        view
        override
        returns (bool)
    {
        if (
            proof.length
                != NO_CERTIFICATE_PUBLIC_VALUES_BYTES
                    + GROTH16_PROOF_BYTES
                && proof.length
                    != CERTIFICATE_PUBLIC_VALUES_BYTES
                        + GROTH16_PROOF_BYTES
        ) return false;
        if (SP1_VERIFIER.codehash != SP1_VERIFIER_CODEHASH) {
            revert VerifierCodeChanged(
                SP1_VERIFIER_CODEHASH, SP1_VERIFIER.codehash
            );
        }
        _requireVerifierIdentity(SP1_VERIFIER);

        uint256 publicValuesLength = proof.length - GROTH16_PROOF_BYTES;
        bytes calldata publicValues = proof[:publicValuesLength];
        bytes calldata groth16Proof = proof[publicValuesLength:];
        if (sha256(publicValues) != publicValuesHash) return false;
        if (
            bytes4(groth16Proof[:4])
                != bytes4(SP1_V610_GROTH16_VERIFIER_HASH)
        ) return false;

        (bool success, bytes memory returned) =
            SP1_VERIFIER.staticcall(
                abi.encodeCall(
                    ISP1VerifierV610.verifyProof,
                    (
                        componentProgramVKey,
                        publicValues,
                        groth16Proof
                    )
                )
            );
        return success && returned.length == 0;
    }

    function _requireVerifierIdentity(address verifier) private view {
        (bool success, bytes memory returned) =
            verifier.staticcall(
                abi.encodeCall(ISP1VerifierV610.VERIFIER_HASH, ())
            );
        bytes32 actual = success && returned.length == 32
            ? abi.decode(returned, (bytes32))
            : bytes32(0);
        if (actual != SP1_V610_GROTH16_VERIFIER_HASH) {
            revert WrongVerifierIdentity(
                SP1_V610_GROTH16_VERIFIER_HASH, actual
            );
        }
    }
}
