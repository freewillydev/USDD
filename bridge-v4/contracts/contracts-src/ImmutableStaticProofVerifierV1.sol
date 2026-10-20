// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISuccinctBip300ProofVerifier} from "./interfaces/ISuccinctBip300ProofVerifier.sol";
import {IProofVerificationComponent} from "./interfaces/IProofVerificationComponent.sol";

/// @title ImmutableStaticProofVerifierV1
/// @notice Ownerless adapter that pins a stateless proof component by address,
///         runtime code hash, proof-program ID, and verifier-configuration hash.
/// @dev The leaf component must be the independently audited transparent proof
///      verifier. This adapter deliberately uses STATICCALL and rejects every
///      noncanonical return value. It has no proxy, owner, setter, delegatecall,
///      or arbitrary call target.
contract ImmutableStaticProofVerifierV1 is ISuccinctBip300ProofVerifier {
    address public immutable COMPONENT;
    bytes32 public immutable COMPONENT_CODEHASH;
    bytes32 public immutable override verifierProgramId;
    bytes32 public immutable override verifierConfigHash;

    error ZeroIdentity();
    error AddressHasNoCode(address target);
    error ComponentCodeChanged(bytes32 expected, bytes32 actual);

    constructor(
        address component,
        bytes32 componentCodehash,
        bytes32 programId,
        bytes32 configHash
    ) {
        if (
            component == address(0) || componentCodehash == bytes32(0) || programId == bytes32(0)
                || configHash == bytes32(0)
        ) revert ZeroIdentity();
        if (component.code.length == 0) revert AddressHasNoCode(component);
        if (component.codehash != componentCodehash) {
            revert ComponentCodeChanged(componentCodehash, component.codehash);
        }
        COMPONENT = component;
        COMPONENT_CODEHASH = componentCodehash;
        verifierProgramId = programId;
        verifierConfigHash = configHash;
    }

    function verifyProof(bytes32 publicValuesHash, bytes calldata proof)
        external
        view
        override
        returns (bool)
    {
        bytes32 actual = COMPONENT.codehash;
        if (actual != COMPONENT_CODEHASH) {
            revert ComponentCodeChanged(COMPONENT_CODEHASH, actual);
        }
        (bool success, bytes memory returndata) = COMPONENT.staticcall(
            abi.encodeCall(IProofVerificationComponent.verify, (publicValuesHash, proof))
        );
        return success && returndata.length == 32 && abi.decode(returndata, (uint256)) == 1;
    }
}
