// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAnchorTransitionProofVerifierV2} from
    "./interfaces/IAnchorTransitionProofVerifierV2.sol";
import {IControllerTransitionProofVerifierV2} from
    "./interfaces/IControllerTransitionProofVerifierV2.sol";
import {ISP1VerifierV610} from "./interfaces/ISP1VerifierV610.sol";

/// @title SP1StrongTransitionProofVerifierV2
/// @notice Immutable SP1 v6.1.0 Groth16 boundary for the V11 controller or
///         Ethereum-anchor acceptance guests.
/// @dev Both guests commit exactly one 32-byte transition statement. `proof`
///      is exactly `statement || groth16Proof`; the statement must equal the
///      relay-supplied public-values hash byte-for-byte. The separate
///      `programId` binds the reproduced guest identity while `programVKey`
///      is the exact BN254 key consumed by the pinned SP1 verifier.
contract SP1StrongTransitionProofVerifierV2 is
    IControllerTransitionProofVerifierV2,
    IAnchorTransitionProofVerifierV2
{
    bytes32 public constant SP1_V610_GROTH16_VERIFIER_HASH =
        0x4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696;
    bytes32 public constant CONFIG_DOMAIN =
        sha256("USDD_V11_SP1_STRONG_TRANSITION_VERIFIER_CONFIG_V2");
    uint32 public constant PUBLIC_VALUES_BYTES = 32;
    uint32 public constant GROTH16_PROOF_BYTES = 356;
    uint32 public constant PROOF_ENVELOPE_BYTES =
        PUBLIC_VALUES_BYTES + GROTH16_PROOF_BYTES;

    address public immutable SP1_VERIFIER;
    bytes32 public immutable SP1_VERIFIER_CODEHASH;
    bytes32 public immutable PROGRAM_VKEY;
    bytes32 public immutable override(IControllerTransitionProofVerifierV2, IAnchorTransitionProofVerifierV2) verifierProgramId;
    bytes32 public immutable override(IControllerTransitionProofVerifierV2, IAnchorTransitionProofVerifierV2) verifierConfigHash;

    error ZeroIdentity();
    error AddressHasNoCode(address target);
    error VerifierCodeChanged(bytes32 expected, bytes32 actual);
    error WrongVerifierIdentity(bytes32 expected, bytes32 actual);

    constructor(
        address sp1Verifier,
        bytes32 sp1VerifierCodehash,
        bytes32 programId,
        bytes32 programVKey
    ) {
        if (
            sp1Verifier == address(0) || sp1VerifierCodehash == bytes32(0)
                || programId == bytes32(0) || programVKey == bytes32(0)
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
        PROGRAM_VKEY = programVKey;
        verifierProgramId = programId;
        verifierConfigHash = sha256(
            abi.encodePacked(
                CONFIG_DOMAIN,
                sp1Verifier,
                sp1VerifierCodehash,
                SP1_V610_GROTH16_VERIFIER_HASH,
                programId,
                programVKey,
                PUBLIC_VALUES_BYTES,
                GROTH16_PROOF_BYTES,
                uint8(1)
            )
        );
    }

    function verifyProof(bytes32 publicValuesHash, bytes calldata proof)
        external
        view
        override(IControllerTransitionProofVerifierV2, IAnchorTransitionProofVerifierV2)
        returns (bool)
    {
        if (proof.length != PROOF_ENVELOPE_BYTES) return false;
        if (SP1_VERIFIER.codehash != SP1_VERIFIER_CODEHASH) {
            revert VerifierCodeChanged(
                SP1_VERIFIER_CODEHASH, SP1_VERIFIER.codehash
            );
        }
        _requireVerifierIdentity(SP1_VERIFIER);

        bytes calldata publicValues = proof[:PUBLIC_VALUES_BYTES];
        bytes calldata groth16Proof = proof[PUBLIC_VALUES_BYTES:];
        bytes32 committedStatement;
        assembly ("memory-safe") {
            committedStatement := calldataload(publicValues.offset)
        }
        if (committedStatement != publicValuesHash) return false;
        if (
            bytes4(groth16Proof[:4])
                != bytes4(SP1_V610_GROTH16_VERIFIER_HASH)
        ) return false;

        (bool success, bytes memory returned) = SP1_VERIFIER.staticcall(
            abi.encodeCall(
                ISP1VerifierV610.verifyProof,
                (PROGRAM_VKEY, publicValues, groth16Proof)
            )
        );
        return success && returned.length == 0;
    }

    function _requireVerifierIdentity(address verifier) private view {
        (bool success, bytes memory returned) = verifier.staticcall(
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
