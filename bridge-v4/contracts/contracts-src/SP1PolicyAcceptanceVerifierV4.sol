// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {IControllerPolicyProofVerifierV4} from "./interfaces/IControllerPolicyProofVerifierV4.sol";
import {ISP1VerifierV610} from "./interfaces/ISP1VerifierV610.sol";

/// @notice Undeployed generic two-word acceptance boundary.
/// @dev Interface ABI reuse does not establish SP1 version compatibility.
/// Deployment must independently qualify the circuit, runtime and guest key.
/// No policy, leaf or bootstrap state is embedded in this verifier.
contract SP1PolicyAcceptanceVerifierV4 is IControllerPolicyProofVerifierV4 {
    bool public constant PRODUCTION_READY = false;
    uint32 public constant PUBLIC_VALUES_BYTES = 64;
    uint32 public constant GROTH16_PROOF_BYTES = 356;
    address public immutable SP1;
    bytes32 public immutable CODEHASH;
    bytes32 public immutable CIRCUIT;
    bytes32 public immutable PROGRAM_VKEY;
    bytes32 public immutable override verifierProgramId;
    bytes32 public immutable override verifierConfigHash;
    error InvalidIdentity();

    constructor(address sp1, bytes32 codehash, bytes32 circuit, bytes32 programId, bytes32 vkey) {
        if (sp1.code.length == 0 || codehash == 0 || sp1.codehash != codehash
            || circuit == 0 || programId == 0 || vkey == 0) revert InvalidIdentity();
        SP1=sp1; CODEHASH=codehash; CIRCUIT=circuit;
        PROGRAM_VKEY=vkey; verifierProgramId=programId;
        if (!_identity()) revert InvalidIdentity();
        verifierConfigHash=sha256(abi.encode(
            keccak256("USDD_V4_POLICY_ACCEPTANCE_VERIFIER"),sp1,codehash,circuit,
            programId,vkey,PUBLIC_VALUES_BYTES,GROTH16_PROOF_BYTES));
    }
    function _identity() private view returns(bool) {
        if (SP1.codehash != CODEHASH) return false;
        (bool ok,bytes memory data)=SP1.staticcall(abi.encodeCall(ISP1VerifierV610.VERIFIER_HASH,()));
        return ok && data.length == 32 && abi.decode(data,(bytes32)) == CIRCUIT;
    }
    function verifyProof(bytes32 statement,bytes32 policyHash,bytes calldata proof)
        external view override returns(bool)
    {
        if (statement == 0 || policyHash == 0 || proof.length != PUBLIC_VALUES_BYTES + GROTH16_PROOF_BYTES
            || !_identity()) return false;
        bytes32 actualStatement; bytes32 actualPolicy;
        assembly ("memory-safe") {
            actualStatement := calldataload(proof.offset)
            actualPolicy := calldataload(add(proof.offset,32))
        }
        if (actualStatement != statement || actualPolicy != policyHash
            || bytes4(proof[64:68]) != bytes4(CIRCUIT)) return false;
        (bool ok,bytes memory data)=SP1.staticcall(abi.encodeCall(ISP1VerifierV610.verifyProof,
            (PROGRAM_VKEY,proof[:64],proof[64:])));
        return ok && data.length == 0;
    }
}
