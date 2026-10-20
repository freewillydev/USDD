// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IProofVerificationComponent} from "../interfaces/IProofVerificationComponent.sol";

/// @notice TEST ONLY. This is not a cryptographic proof verifier.
contract MockProofVerificationComponent is IProofVerificationComponent {
    function verify(bytes32 publicValuesHash, bytes calldata proof)
        external
        pure
        returns (bool)
    {
        return proof.length == 32 && bytes32(proof) == publicValuesHash;
    }
}
