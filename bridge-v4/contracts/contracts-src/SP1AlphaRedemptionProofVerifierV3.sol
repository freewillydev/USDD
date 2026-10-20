// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISP1VerifierV610} from "./interfaces/ISP1VerifierV610.sol";
import {IUSDDRedemptionProofVerifierV2} from "./interfaces/IUSDDRedemptionProofVerifierV2.sol";
import {IParentFinalityRelayV2} from "./interfaces/IParentFinalityRelayV2.sol";

/// @notice Candidate boundary for the Alpha custody v3 144-byte journal.
/// @dev NOT a qualified release. Exact guest/circuit and immutable non-proxy
/// relay implementations must be independently reviewed before deployment.
contract SP1AlphaRedemptionProofVerifierV3 is IUSDDRedemptionProofVerifierV2 {
    uint32 public constant PUBLIC_VALUES_BYTES = 144;
    uint32 public constant GROTH16_PROOF_BYTES = 356;
    bytes32 public constant CONFIG_DOMAIN = sha256("USDD_ALPHA_REDEMPTION_VERIFIER_V3");
    bytes32 public constant override securityModelId =
        keccak256("USDD_ELEMENTS_BURN_SLOT24_SIX_NET_ACKS_V1");
    struct Parameters {
        address sp1;
        bytes32 sp1Codehash;
        bytes32 circuit;
        bytes32 program;
        bytes32 vkey;
        bytes32 release;
        address relay;
        bytes32 relayCodehash;
        bytes32 parentIdentity;
        bytes32 finalityConfig;
        uint64 maximumAge;
    }
    address public immutable SP1;
    bytes32 public immutable SP1_CODEHASH;
    bytes32 public immutable CIRCUIT;
    bytes32 public immutable VKEY;
    bytes32 public immutable RELEASE;
    address public immutable RELAY;
    bytes32 public immutable RELAY_CODEHASH;
    bytes32 public immutable PARENT_IDENTITY;
    bytes32 public immutable FINALITY_CONFIG;
    uint64 public immutable MAXIMUM_AGE;
    bytes32 public immutable override verifierProgramId;
    bytes32 public immutable override verifierConfigHash;
    error InvalidConfiguration();

    constructor(Parameters memory p) {
        if (p.sp1.code.length == 0 || p.relay.code.length == 0
            || p.sp1Codehash == 0 || p.relayCodehash == 0
            || p.sp1.codehash != p.sp1Codehash || p.relay.codehash != p.relayCodehash
            || p.circuit == 0 || p.program == 0 || p.vkey == 0 || p.release == 0
            || p.parentIdentity == 0 || p.finalityConfig == 0 || p.maximumAge == 0)
            revert InvalidConfiguration();
        SP1 = p.sp1; SP1_CODEHASH = p.sp1Codehash; CIRCUIT = p.circuit;
        VKEY = p.vkey; RELEASE = p.release; RELAY = p.relay;
        RELAY_CODEHASH = p.relayCodehash; PARENT_IDENTITY = p.parentIdentity;
        FINALITY_CONFIG = p.finalityConfig; MAXIMUM_AGE = p.maximumAge;
        verifierProgramId = p.program;
        // Includes the exact clock rule (1 = observation equals authenticated MTP).
        verifierConfigHash = sha256(abi.encode(CONFIG_DOMAIN, securityModelId, p,
            PUBLIC_VALUES_BYTES, GROTH16_PROOF_BYTES, uint8(1)));
        if (!_identities()) revert InvalidConfiguration();
    }

    function _word(address target, bytes4 selector, bytes32 expected) private view returns (bool) {
        (bool ok, bytes memory data) = target.staticcall(abi.encodeWithSelector(selector));
        return ok && data.length == 32 && abi.decode(data, (bytes32)) == expected;
    }
    function _identities() private view returns (bool) {
        return SP1.codehash == SP1_CODEHASH && RELAY.codehash == RELAY_CODEHASH
            && _word(SP1, ISP1VerifierV610.VERIFIER_HASH.selector, CIRCUIT)
            && _word(RELAY, IParentFinalityRelayV2.parentChainIdentity.selector, PARENT_IDENTITY)
            && _word(RELAY, IParentFinalityRelayV2.finalityConfigHash.selector, FINALITY_CONFIG);
    }
    function verify(bytes32 statement, bytes calldata proof) external view override returns (bool) {
        if (proof.length != PUBLIC_VALUES_BYTES + GROTH16_PROOF_BYTES || !_identities()) return false;
        bytes calldata values = proof[:PUBLIC_VALUES_BYTES];
        if (bytes32(values[:32]) != RELEASE || bytes32(values[32:64]) != statement) return false;
        bytes32 parentHash = bytes32(values[64:96]);
        uint64 height = uint32(bytes4(values[96:100]));
        uint64 mtp = uint32(bytes4(values[100:104]));
        uint256 work = uint256(bytes32(values[104:136]));
        uint64 observation = uint64(bytes8(values[136:144]));
        // Clock comes from the authenticated parent tuple, never the prover.
        if (parentHash == 0 || work == 0 || mtp == 0 || observation != mtp
            || observation > block.timestamp || block.timestamp - observation > MAXIMUM_AGE) return false;
        (bool memberOk, bytes memory member) = RELAY.staticcall(abi.encodeCall(
            IParentFinalityRelayV2.isFinalizedCanonical, (parentHash, height, mtp, work)));
        if (!memberOk || member.length != 32) return false;
        uint256 membership;
        assembly ("memory-safe") { membership := mload(add(member, 32)) }
        if (membership != 1) return false;
        bytes calldata groth16 = proof[PUBLIC_VALUES_BYTES:];
        if (bytes4(groth16[:4]) != bytes4(CIRCUIT)) return false;
        (bool ok, bytes memory returned) = SP1.staticcall(abi.encodeCall(
            ISP1VerifierV610.verifyProof, (VKEY, values, groth16)));
        return ok && returned.length == 0;
    }
}
