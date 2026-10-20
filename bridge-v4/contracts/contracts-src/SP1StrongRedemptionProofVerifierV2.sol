// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISP1VerifierV610} from "./interfaces/ISP1VerifierV610.sol";
import {IUSDDRedemptionProofVerifierV2} from
    "./interfaces/IUSDDRedemptionProofVerifierV2.sol";

/// @title SP1StrongRedemptionProofVerifierV2
/// @notice Immutable SP1 v6.1.0 Groth16 boundary for the V11 burn/M3-M4-M6
///         redemption statement consumed by `USDDVaultV2`.
contract SP1StrongRedemptionProofVerifierV2 is
    IUSDDRedemptionProofVerifierV2
{
    bytes32 public constant SP1_V610_GROTH16_VERIFIER_HASH =
        0x4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696;
    bytes32 public constant REQUIRED_SECURITY_MODEL_ID = keccak256(
        "USDD_V11_STRONG_RECURSIVE_ELEMENTS_BURN_AND_M6_PROFILE"
    );
    bytes32 public constant CONFIG_DOMAIN =
        sha256("USDD_V11_SP1_STRONG_REDEMPTION_VERIFIER_CONFIG_V2");
    uint32 public constant PUBLIC_VALUES_BYTES = 32;
    uint32 public constant GROTH16_PROOF_BYTES = 356;
    uint32 public constant PROOF_ENVELOPE_BYTES =
        PUBLIC_VALUES_BYTES + GROTH16_PROOF_BYTES;

    address public immutable SP1_VERIFIER;
    bytes32 public immutable SP1_VERIFIER_CODEHASH;
    bytes32 public immutable PROGRAM_VKEY;
    bytes32 public immutable override securityModelId;
    bytes32 public immutable override verifierProgramId;
    bytes32 public immutable override verifierConfigHash;

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
        securityModelId = REQUIRED_SECURITY_MODEL_ID;
        verifierProgramId = programId;
        verifierConfigHash = sha256(
            abi.encodePacked(
                CONFIG_DOMAIN,
                REQUIRED_SECURITY_MODEL_ID,
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

    function verify(bytes32 statement, bytes calldata proof)
        external
        view
        override
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
        if (committedStatement != statement) return false;
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
